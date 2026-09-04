package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ATT-CSO/control-translation/go-api/internal/databricks"
	"github.com/ATT-CSO/control-translation/go-api/internal/lifecycle"
	"github.com/ATT-CSO/control-translation/go-api/internal/store"
	"github.com/ATT-CSO/control-translation/go-api/internal/store/storetest"
	"github.com/ATT-CSO/control-translation/go-api/internal/upstream"
)

const provenSecRule = `SecRule ARGS:Researcher "@rx (?i)(?:'\\s+OR\\s+'1'='1|` +
	`%27\\s*(?:OR|%4f%52)\\s*%271%27%3[dD]%271)" ` +
	`"id:152405,phase:2,deny,status:403,log,tag:'janus-candidate'"`

func newTestServer(t *testing.T) (http.Handler, *storetest.FakeWorkspace) {
	t.Helper()
	fake := storetest.NewFakeWorkspace(t)
	settings := storetest.FakeSettings()
	client := databricks.NewWithBaseURL(settings, fake.Server.URL)
	repository, err := store.New(settings, client)
	if err != nil {
		t.Fatalf("unable to open the store: %v", err)
	}
	server := New(settings, repository, upstream.NewResolver(settings, client), newQueue(t))
	server.Start()
	t.Cleanup(server.Stop)
	return server.Handler(), fake
}

// newQueue opens a lifecycle queue in the test's temporary directory.
func newQueue(t *testing.T) *lifecycle.Store {
	t.Helper()
	queue, err := lifecycle.Open(filepath.Join(t.TempDir(), "lifecycle.db"))
	if err != nil {
		t.Fatalf("unable to open the lifecycle queue: %v", err)
	}
	t.Cleanup(func() { _ = queue.Close() })
	return queue
}

// newServerWithoutResolver models a deployment with no Databricks reader.
func newServerWithoutResolver(t *testing.T) http.Handler {
	t.Helper()
	fake := storetest.NewFakeWorkspace(t)
	settings := storetest.FakeSettings()
	repository, err := store.New(settings, databricks.NewWithBaseURL(settings, fake.Server.URL))
	if err != nil {
		t.Fatalf("unable to open the store: %v", err)
	}
	return New(settings, repository, nil, newQueue(t)).Handler()
}

func requestBody(patternSummary string) string {
	body := map[string]any{
		"input": map[string]any{
			"proven_pattern": map[string]any{
				"proven_pattern_id":         "proven-pattern:test",
				"vulnerability_id":          "CVE-2026-77392",
				"selected_control_class":    "waf",
				"discriminator_id":          "discriminator:test",
				"discriminator_description": "Blocks the proven exploitation request.",
				"pattern_summary":           patternSummary,
				"proof_record_ids": []string{
					"mitigation-check-result:a", "bypass-validation-result:b",
				},
			},
			"target_context": map[string]any{
				"target_technology":        "akamai-waf",
				"target_policy_context_id": "akamai-policy:example:rev-17",
			},
		},
	}
	encoded, _ := json.Marshal(body)
	return string(encoded)
}

func post(t *testing.T, handler http.Handler, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

func get(t *testing.T, handler http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	return recorder
}

func decode(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response is not JSON: %v\n%s", err, recorder.Body.String())
	}
	return payload
}

// ---------------------------------------------------------------------------
// Status surface
// ---------------------------------------------------------------------------

func TestServiceDescriptor(t *testing.T) {
	handler, _ := newTestServer(t)

	payload := decode(t, get(t, handler, "/"))

	if payload["service"] != "control-translation" || payload["role"] != "api" {
		t.Errorf("unexpected service descriptor: %v", payload)
	}
}

func TestHealthAndReadiness(t *testing.T) {
	handler, _ := newTestServer(t)

	if got := decode(t, get(t, handler, "/health"))["status"]; got != "ok" {
		t.Errorf("health = %v, want ok", got)
	}
	if got := decode(t, get(t, handler, "/ready"))["status"]; got != "ready" {
		t.Errorf("ready = %v, want ready", got)
	}
}

// Databricks is the only backend, so an unreachable warehouse must keep the
// service out of rotation rather than let it accept work it cannot persist.
func TestReadinessFailsWhenDatabricksIsUnreachable(t *testing.T) {
	handler, fake := newTestServer(t)
	fake.Fail = true

	recorder := get(t, handler, "/ready")

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready = %d, want 503", recorder.Code)
	}
	if decode(t, recorder)["detail"].(map[string]any)["storage"] != "unavailable" {
		t.Errorf("readiness should name storage as the cause: %s", recorder.Body.String())
	}
}

func TestReadinessFailsWhenDatabricksIsNotConfigured(t *testing.T) {
	fake := storetest.NewFakeWorkspace(t)
	settings := storetest.FakeSettings()
	settings.DatabricksToken = "" // PAT auth with no token
	repository, err := store.New(settings, databricks.NewWithBaseURL(settings, fake.Server.URL))
	if err != nil {
		t.Fatalf("unable to open the store: %v", err)
	}
	handler := New(settings, repository, nil, newQueue(t)).Handler()

	recorder := get(t, handler, "/ready")

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready = %d, want 503", recorder.Code)
	}
	errors := decode(t, recorder)["detail"].(map[string]any)["configuration_errors"].([]any)
	if len(errors) == 0 || !strings.Contains(errors[0].(string), "DATABRICKS_TOKEN") {
		t.Errorf("readiness should name the missing setting: %v", errors)
	}
}

// This build has no model client, so live mode must refuse to start rather
// than serve deterministic output while claiming to be live.
func TestLiveModeIsRefused(t *testing.T) {
	settings := storetest.FakeSettings()
	settings.RunMode = "live"

	problems := settings.ConfigurationErrors()

	found := false
	for _, problem := range problems {
		if strings.Contains(problem, "no model client") {
			found = true
		}
	}
	if !found {
		t.Errorf("live mode must be refused explicitly: %v", problems)
	}
}

func TestStatusEndpointsNeverReturnSecrets(t *testing.T) {
	fake := storetest.NewFakeWorkspace(t)
	settings := storetest.FakeSettings()
	settings.DatabricksToken = "super-secret-pat"
	settings.DatabricksClientSecret = "super-secret-oauth"
	repository, _ := store.New(settings, databricks.NewWithBaseURL(settings, fake.Server.URL))
	handler := New(settings, repository, nil, newQueue(t)).Handler()

	for _, path := range []string{"/", "/inference", "/schema", "/ready"} {
		body := get(t, handler, path).Body.String()
		for _, secret := range []string{"super-secret-pat", "super-secret-oauth"} {
			if strings.Contains(body, secret) {
				t.Errorf("%s leaked a credential", path)
			}
		}
	}
}

// The advertised contract must match what the build accepts, or a consumer
// integrating from /schema will send fields that come back as 422.
func TestSchemaAdvertisesTheFieldsThisBuildAccepts(t *testing.T) {
	handler, _ := newTestServer(t)

	payload := decode(t, get(t, handler, "/schema"))

	var fields []string
	for _, item := range payload["request_model_fields"].([]any) {
		fields = append(fields, item.(string))
	}
	required := map[string]bool{
		"input": false, "contract_id": false, "subject": false,
		"upstream_inputs": false, "routing_context": false,
	}
	for _, field := range fields {
		if _, wanted := required[field]; wanted {
			required[field] = true
		}
		if field == "callback" {
			t.Error("/schema advertises callback, which this build rejects")
		}
	}
	for field, present := range required {
		if !present {
			t.Errorf("/schema does not advertise %q, which this build accepts", field)
		}
	}
	if paths := payload["execution_paths"].([]any); len(paths) != 1 ||
		paths[0] != "deterministic-modsec-rule" {
		t.Errorf("execution_paths = %v", paths)
	}
}

func TestSchemaAdvertisesOnlyAkamai(t *testing.T) {
	handler, _ := newTestServer(t)

	payload := decode(t, get(t, handler, "/schema"))

	adapters := payload["supported_adapters"].(map[string]any)
	if len(adapters) != 1 {
		t.Fatalf("this build supports one target technology, got %v", adapters)
	}
	if _, ok := adapters["akamai-waf"]; !ok {
		t.Errorf("akamai-waf is missing: %v", adapters)
	}
	if payload["persistence"] != "databricks" {
		t.Errorf("persistence = %v, want databricks", payload["persistence"])
	}
}

// ---------------------------------------------------------------------------
// The one execution path
// ---------------------------------------------------------------------------

func TestInvokeCompilesTheProvenRule(t *testing.T) {
	handler, fake := newTestServer(t)

	recorder := post(t, handler, "/invoke", requestBody(provenSecRule))

	if recorder.Code != http.StatusOK {
		t.Fatalf("invoke = %d: %s", recorder.Code, recorder.Body.String())
	}
	payload := decode(t, recorder)
	if payload["terminal_state"] != "translated" {
		t.Fatalf("terminal_state = %v", payload["terminal_state"])
	}
	inference := payload["inference"].(map[string]any)
	if inference["proposal_source"] != "deterministic-modsec-rule" || inference["llm_invoked"] != false {
		t.Errorf("unexpected inference block: %v", inference)
	}
	candidate := payload["structured_result"].(map[string]any)["primary_candidate"].(map[string]any)
	artifact := candidate["candidate_artifact"].(map[string]any)
	if artifact["artifact_type"] != "akamai-waf-rule" ||
		!strings.HasPrefix(artifact["content_hash"].(string), "sha256:") {
		t.Errorf("unexpected artifact: %v", artifact)
	}
	if len(fake.Rows()) != 1 {
		t.Errorf("the result should have been persisted once, got %d rows", len(fake.Rows()))
	}
}

// A rule the compiler cannot express is a typed decline, never a guess and
// never a model call: there is no model in this build.
func TestUnmappableRuleCannotBeExpressed(t *testing.T) {
	handler, _ := newTestServer(t)

	payload := decode(t, post(t, handler, "/invoke",
		requestBody(`SecRule ARGS:u "@rx ^a\\s{2,}b$" "id:8,deny"`)))

	if payload["terminal_state"] != "cannot-express" || payload["status"] != "declined" {
		t.Fatalf("terminal_state = %v, want cannot-express", payload["terminal_state"])
	}
	reason := payload["structured_result"].(map[string]any)["outcome_reason"].(map[string]any)
	if reason["code"] != "unsupported-feature" {
		t.Errorf("reason = %v", reason)
	}
	if payload["structured_result"].(map[string]any)["primary_candidate"] != nil {
		t.Error("a declined translation must not produce a candidate")
	}
}

func TestProseAndPatternSummaryAreNotConfused(t *testing.T) {
	handler, _ := newTestServer(t)

	payload := decode(t, post(t, handler, "/invoke",
		requestBody("Block requests whose Content-Type header contains OGNL syntax.")))

	if payload["terminal_state"] != "cannot-express" {
		t.Errorf("prose is not a rule and must not translate: %v", payload["terminal_state"])
	}
}

func TestInsufficientContextWhenNoSnapshotExists(t *testing.T) {
	handler, _ := newTestServer(t)
	body := strings.Replace(requestBody(provenSecRule),
		"akamai-policy:example:rev-17", "akamai-policy:does-not-exist", 1)

	payload := decode(t, post(t, handler, "/invoke", body))

	if payload["terminal_state"] != "insufficient-context" {
		t.Errorf("terminal_state = %v, want insufficient-context", payload["terminal_state"])
	}
}

func TestTranslationPolicyCanRefuseNarrowerCandidates(t *testing.T) {
	handler, _ := newTestServer(t)
	body := strings.Replace(requestBody(provenSecRule), `"target_context"`,
		`"translation_policy":{"allow_narrower_translation":false},"target_context"`, 1)

	payload := decode(t, post(t, handler, "/invoke", body))

	if payload["terminal_state"] != "cannot-express" {
		t.Fatalf("terminal_state = %v, want cannot-express", payload["terminal_state"])
	}
	detail := payload["structured_result"].(map[string]any)["outcome_reason"].(map[string]any)["detail"]
	if !strings.Contains(detail.(string), "narrower") {
		t.Errorf("detail should name the refused label: %v", detail)
	}
}

func TestInvokeRejectsUnknownFields(t *testing.T) {
	handler, _ := newTestServer(t)

	if code := post(t, handler, "/invoke", `{"input":{},"not_a_field":1}`).Code; code != http.StatusUnprocessableEntity {
		t.Errorf("unknown field = %d, want 422", code)
	}
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

func TestIdempotentInvokeReturnsTheOriginalResult(t *testing.T) {
	handler, fake := newTestServer(t)
	body := strings.Replace(requestBody(provenSecRule), `{"input"`,
		`{"request_id":"req-1","idempotency_key":"req-1","input"`, 1)

	first := decode(t, post(t, handler, "/invoke", body))
	second := decode(t, post(t, handler, "/invoke", body))

	if first["result_id"] != second["result_id"] {
		t.Error("a repeated idempotency key must return the same result")
	}
	if len(fake.Rows()) != 1 {
		t.Errorf("a retry must not write a second row, got %d", len(fake.Rows()))
	}

	changed := strings.Replace(body, "CVE-2026-77392", "CVE-2020-0001", 1)
	if code := post(t, handler, "/invoke", changed).Code; code != http.StatusConflict {
		t.Errorf("reusing a key for different input = %d, want 409", code)
	}
}

func TestRunAndResultAreDurablyReadable(t *testing.T) {
	handler, _ := newTestServer(t)
	created := decode(t, post(t, handler, "/invoke", requestBody(provenSecRule)))

	run := decode(t, get(t, handler, "/runs/"+created["run_id"].(string)))
	if run["result_id"] != created["result_id"] {
		t.Error("the durable run does not match the original response")
	}
	result := decode(t, get(t, handler, "/v1/results/"+created["result_id"].(string)))
	if result["terminal_state"] != "translated" {
		t.Errorf("durable result = %v", result["terminal_state"])
	}
	if code := get(t, handler, "/runs/does-not-exist").Code; code != http.StatusNotFound {
		t.Errorf("missing run = %d, want 404", code)
	}
}

func TestRunsDashboardExcludesRequestAndArtifactContent(t *testing.T) {
	handler, _ := newTestServer(t)
	post(t, handler, "/invoke", requestBody(provenSecRule))

	payload := decode(t, get(t, handler, "/v1/runs?limit=5&offset=0"))

	items := payload["items"].([]any)
	if len(items) != 1 || payload["total"].(float64) != 1 {
		t.Fatalf("unexpected page: %v", payload)
	}
	item := items[0].(map[string]any)
	for _, forbidden := range []string{"request_json", "content_ref", "candidate_artifact"} {
		if _, present := item[forbidden]; present {
			t.Errorf("run summary must not expose %s", forbidden)
		}
	}
	if item["artifact_type"] != "akamai-waf-rule" || item["vulnerability_id"] != "CVE-2026-77392" {
		t.Errorf("unexpected summary: %v", item)
	}
}

func TestRunListPaginationIsBounded(t *testing.T) {
	handler, _ := newTestServer(t)

	for _, query := range []string{"?limit=0", "?limit=101", "?offset=-1", "?limit=abc"} {
		if code := get(t, handler, "/v1/runs"+query).Code; code != http.StatusUnprocessableEntity {
			t.Errorf("/v1/runs%s = %d, want 422", query, code)
		}
	}
}

// A workspace failure is a sanitized 503: the statement and the root cause
// stay in server logs.
func TestStorageFailureIsSanitized(t *testing.T) {
	handler, fake := newTestServer(t)
	fake.Fail = true

	recorder := post(t, handler, "/invoke", requestBody(provenSecRule))

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("invoke with a failing warehouse = %d, want 503", recorder.Code)
	}
	body := recorder.Body.String()
	if strings.Contains(body, "MERGE INTO") || strings.Contains(body, "fake-pat") {
		t.Errorf("the error body leaked SQL or a credential: %s", body)
	}
	detail := decode(t, recorder)["detail"].(map[string]any)
	if detail["code"] != "storage_unavailable" || detail["retryable"] != true {
		t.Errorf("unexpected error envelope: %v", detail)
	}
}

// ---------------------------------------------------------------------------
// CORS
// ---------------------------------------------------------------------------

func TestCORSAllowsOnlyTheConfiguredOrigin(t *testing.T) {
	handler, _ := newTestServer(t)

	for origin, want := range map[string]string{
		"http://127.0.0.1:8080": "http://127.0.0.1:8080",
		"https://evil.example":  "",
	} {
		request := httptest.NewRequest(http.MethodOptions, "/invoke", nil)
		request.Header.Set("Origin", origin)
		request.Header.Set("Access-Control-Request-Method", "POST")
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		if got := recorder.Header().Get("Access-Control-Allow-Origin"); got != want {
			t.Errorf("origin %s: allow-origin = %q, want %q", origin, got, want)
		}
	}
}

func TestCORSIsClosedWhenNoOriginIsConfigured(t *testing.T) {
	fake := storetest.NewFakeWorkspace(t)
	settings := storetest.FakeSettings()
	settings.CORSAllowedOrigins = nil
	repository, _ := store.New(settings, databricks.NewWithBaseURL(settings, fake.Server.URL))
	handler := New(settings, repository, nil, newQueue(t)).Handler()

	request := httptest.NewRequest(http.MethodGet, "/health", nil)
	request.Header.Set("Origin", "http://127.0.0.1:8080")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	if recorder.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("browser access must be closed until an origin is configured")
	}
}
