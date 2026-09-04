package httpapi

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/ATT-CSO/control-translation/go-api/internal/databricks"
	"github.com/ATT-CSO/control-translation/go-api/internal/store"
	"github.com/ATT-CSO/control-translation/go-api/internal/store/storetest"
)

func openAPIPaths(t *testing.T, handler http.Handler) map[string]map[string]any {
	t.Helper()
	recorder := get(t, handler, "/openapi.json")
	if recorder.Code != http.StatusOK {
		t.Fatalf("/openapi.json = %d", recorder.Code)
	}
	var document struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatalf("the document is not valid JSON: %v", err)
	}
	return document.Paths
}

// A hand-written spec that drifts from the code is worse than no spec, so the
// document and the route table are held to each other in both directions.
func TestOpenAPIDocumentMatchesTheRouteTable(t *testing.T) {
	server, _ := newTestServerAndFake(t)
	handler := server.Handler()
	documented := openAPIPaths(t, handler)

	routed := map[string]map[string]bool{}
	for _, entry := range append(server.routes(), server.documentationRoutes()...) {
		if routed[entry.path] == nil {
			routed[entry.path] = map[string]bool{}
		}
		routed[entry.path][strings.ToLower(entry.method)] = true
	}

	for path, methods := range routed {
		operations, present := documented[path]
		if !present {
			t.Errorf("route %s is not in the OpenAPI document", path)
			continue
		}
		for method := range methods {
			if _, ok := operations[method]; !ok {
				t.Errorf("route %s %s is not in the OpenAPI document", strings.ToUpper(method), path)
			}
		}
	}
	for path, operations := range documented {
		methods, present := routed[path]
		if !present {
			t.Errorf("the OpenAPI document describes %s, which is not routed", path)
			continue
		}
		for method := range operations {
			if !methods[method] {
				t.Errorf("the OpenAPI document describes %s %s, which is not routed",
					strings.ToUpper(method), path)
			}
		}
	}
}

// The terminal states the document advertises must be the ones the service can
// actually emit, or a caller writing a switch against it will miss a case.
func TestOpenAPIAdvertisesEveryTerminalState(t *testing.T) {
	server, _ := newTestServerAndFake(t)
	recorder := get(t, server.Handler(), "/openapi.json")

	var document struct {
		Components struct {
			Schemas struct {
				TerminalState struct {
					Enum []string `json:"enum"`
				} `json:"TerminalState"`
			} `json:"schemas"`
		} `json:"components"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &document); err != nil {
		t.Fatalf("the document is not valid JSON: %v", err)
	}
	got := append([]string{}, document.Components.Schemas.TerminalState.Enum...)
	want := []string{
		"cannot-express", "insufficient-context", "malfunction",
		"scope-declined", "translated",
	}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("documented terminal states = %v, want %v", got, want)
	}
}

func TestSwaggerAndRedocRenderTheDocument(t *testing.T) {
	server, _ := newTestServerAndFake(t)
	handler := server.Handler()

	for path, marker := range map[string]string{
		"/docs":  "SwaggerUIBundle",
		"/redoc": "<redoc",
	} {
		recorder := get(t, handler, path)
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s = %d", path, recorder.Code)
		}
		if contentType := recorder.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
			t.Errorf("%s content-type = %q", path, contentType)
		}
		body := recorder.Body.String()
		if !strings.Contains(body, marker) || !strings.Contains(body, "/openapi.json") {
			t.Errorf("%s does not render the document: %s", path, body)
		}
	}
}

// ENABLE_DOCS=false removes the routes entirely, so a closed deployment does
// not publish its own surface, and the descriptor stops advertising them.
func TestDocumentationIsAbsentWhenDisabled(t *testing.T) {
	fake := storetest.NewFakeWorkspace(t)
	settings := storetest.FakeSettings()
	settings.EnableDocs = false
	repository, err := store.New(settings, databricks.NewWithBaseURL(settings, fake.Server.URL))
	if err != nil {
		t.Fatalf("unable to open the store: %v", err)
	}
	handler := New(settings, repository, nil, newQueue(t)).Handler()

	for _, path := range []string{"/openapi.json", "/docs", "/redoc"} {
		if code := get(t, handler, path).Code; code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404 when ENABLE_DOCS is false", path, code)
		}
	}
	descriptor := decode(t, get(t, handler, "/"))
	if descriptor["docs"] != nil || descriptor["openapi"] != nil {
		t.Errorf("the descriptor should not advertise absent docs: %v", descriptor)
	}
}

// The descriptor's docs field used to point at a route that did not exist.
func TestDescriptorAdvertisesDocumentationThatExists(t *testing.T) {
	server, _ := newTestServerAndFake(t)
	handler := server.Handler()

	descriptor := decode(t, get(t, handler, "/"))
	for _, field := range []string{"docs", "openapi"} {
		path, ok := descriptor[field].(string)
		if !ok {
			t.Fatalf("descriptor %s = %v", field, descriptor[field])
		}
		if code := get(t, handler, path).Code; code != http.StatusOK {
			t.Errorf("the descriptor advertises %s, which returns %d", path, code)
		}
	}
}
