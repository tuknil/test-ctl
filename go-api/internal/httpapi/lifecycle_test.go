package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The asynchronous lifecycle: the queue is a local SQLite file, the immutable
// result goes to Databricks, and the queue row only points at it.

func asyncHeaders(requestID string) map[string]string {
	return map[string]string{
		"Idempotency-Key":  requestID,
		"X-Correlation-ID": "corr-" + requestID,
	}
}

func submit(t *testing.T, handler http.Handler, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/v1/control-translation-runs",
		strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder
}

// asyncBody is a direct proven-pattern request carrying the transport identity
// the async route requires.
func asyncBody(requestID string) string {
	return strings.Replace(requestBody(provenSecRule), `{"input"`,
		`{"request_id":"`+requestID+`","correlation_id":"corr-`+requestID+`","input"`, 1)
}

func waitForStatus(t *testing.T, handler http.Handler, runID, want string) map[string]any {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		payload := decode(t, get(t, handler, "/v1/control-translation-runs/"+runID))
		if payload["status"] == want {
			return payload
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("run %s never reached status %q", runID, want)
	return nil
}

func TestAsyncRunIsQueuedProcessedAndPollable(t *testing.T) {
	handler, fake := newTestServer(t)

	recorder := submit(t, handler, asyncBody("run-1"), asyncHeaders("run-1"))
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("submit = %d: %s", recorder.Code, recorder.Body.String())
	}
	submission := decode(t, recorder)
	if submission["status"] != "queued" {
		t.Errorf("a submission must start queued, got %v", submission["status"])
	}
	runID := submission["run_id"].(string)

	status := waitForStatus(t, handler, runID, "completed")
	if status["terminal_state"] != "translated" {
		t.Fatalf("terminal_state = %v", status["terminal_state"])
	}

	// The completion carries integrity metadata, not the result itself.
	completion := status["completion"].(map[string]any)
	if !strings.HasPrefix(completion["content_sha256"].(string), "sha256:") ||
		completion["size_bytes"].(float64) <= 0 {
		t.Errorf("completion lacks integrity metadata: %v", completion)
	}
	if completion["result_id"] != status["result_id"] {
		t.Errorf("completion and status disagree on the result id")
	}

	// The immutable result went to Databricks, and the result route reads it
	// back from there.
	if len(fake.Rows()) != 1 {
		t.Fatalf("the result should be in Databricks, got %d rows", len(fake.Rows()))
	}
	result := decode(t, get(t, handler, "/v1/control-translation-runs/"+runID+"/result"))
	if result["result_id"] != status["result_id"] {
		t.Errorf("the polled result does not match the completion")
	}
	if result["terminal_state"] != "translated" {
		t.Errorf("polled result = %v", result["terminal_state"])
	}
}

func TestAsyncSubmissionRequiresItsTransportHeaders(t *testing.T) {
	handler, _ := newTestServer(t)

	cases := map[string]struct {
		headers map[string]string
		body    string
		want    int
	}{
		"missing headers":     {nil, asyncBody("run-2"), http.StatusBadRequest},
		"request id mismatch": {asyncHeaders("other"), asyncBody("run-2"), http.StatusBadRequest},
		"correlation mismatch": {
			map[string]string{"Idempotency-Key": "run-2", "X-Correlation-ID": "wrong"},
			asyncBody("run-2"), http.StatusBadRequest,
		},
		"partial callback header group": {
			map[string]string{
				"Idempotency-Key": "run-2", "X-Correlation-ID": "corr-run-2",
				"X-Janus-Callback-URL": "https://orchestration.example/callback",
			},
			asyncBody("run-2"), http.StatusBadRequest,
		},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			recorder := submit(t, handler, testCase.body, testCase.headers)
			if recorder.Code != testCase.want {
				t.Errorf("got %d, want %d: %s", recorder.Code, testCase.want, recorder.Body.String())
			}
		})
	}
}

func TestAsyncSubmissionRequiresJSONContentType(t *testing.T) {
	handler, _ := newTestServer(t)
	request := httptest.NewRequest(http.MethodPost, "/v1/control-translation-runs",
		strings.NewReader("{}"))
	request.Header.Set("Content-Type", "text/plain")
	request.Header.Set("Idempotency-Key", "run-3")
	request.Header.Set("X-Correlation-ID", "corr-run-3")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Errorf("a non-JSON submission = %d, want 400", recorder.Code)
	}
	if decode(t, recorder)["code"] != "invalid_content_type" {
		t.Errorf("unexpected error code: %s", recorder.Body.String())
	}
}

func TestAsyncSubmissionIsIdempotent(t *testing.T) {
	handler, fake := newTestServer(t)

	first := decode(t, submit(t, handler, asyncBody("run-4"), asyncHeaders("run-4")))
	repeat := submit(t, handler, asyncBody("run-4"), asyncHeaders("run-4"))
	if repeat.Code != http.StatusOK {
		t.Errorf("an identical retry = %d, want 200", repeat.Code)
	}
	if decode(t, repeat)["run_id"] != first["run_id"] {
		t.Error("an identical retry must return the same run")
	}

	changed := strings.Replace(asyncBody("run-4"), "CVE-2026-77392", "CVE-2020-0001", 1)
	if code := submit(t, handler, changed, asyncHeaders("run-4")).Code; code != http.StatusConflict {
		t.Errorf("reusing a key for different input = %d, want 409", code)
	}

	waitForStatus(t, handler, first["run_id"].(string), "completed")
	if len(fake.Rows()) != 1 {
		t.Errorf("one submission must produce one result row, got %d", len(fake.Rows()))
	}
}

func TestPollingAMissingRunIsTyped(t *testing.T) {
	handler, _ := newTestServer(t)

	for _, path := range []string{
		"/v1/control-translation-runs/does-not-exist",
		"/v1/control-translation-runs/does-not-exist/result",
	} {
		recorder := get(t, handler, path)
		if recorder.Code != http.StatusNotFound {
			t.Errorf("%s = %d, want 404", path, recorder.Code)
		}
		if decode(t, recorder)["code"] != "run_not_found" {
			t.Errorf("%s: unexpected body %s", path, recorder.Body.String())
		}
	}
}

// Cancellation wins before a result exists; afterwards the completion wins,
// because the result is already in the immutable results table.
func TestCancellationIsIdempotentAndNeverUndoesACompletion(t *testing.T) {
	handler, _ := newTestServer(t)
	submission := decode(t, submit(t, handler, asyncBody("run-5"), asyncHeaders("run-5")))
	runID := submission["run_id"].(string)
	waitForStatus(t, handler, runID, "completed")

	first := post(t, handler, "/v1/control-translation-runs/"+runID+"/cancel", "")
	if first.Code != http.StatusAccepted {
		t.Fatalf("cancel = %d", first.Code)
	}
	if decode(t, first)["status"] != "completed" {
		t.Error("cancellation must not undo a completed run")
	}
	second := post(t, handler, "/v1/control-translation-runs/"+runID+"/cancel", "")
	if second.Code != http.StatusAccepted || decode(t, second)["status"] != "completed" {
		t.Error("cancellation must be idempotent")
	}
	if code := post(t, handler, "/v1/control-translation-runs/missing/cancel", "").Code; code != http.StatusNotFound {
		t.Errorf("cancelling a missing run = %d, want 404", code)
	}
}

// A workspace that cannot accept the result must not leave the run reported as
// completed.
func TestAsyncRunDoesNotCompleteWhenTheResultCannotBePublished(t *testing.T) {
	handler, fake := newTestServer(t)
	fake.Fail = true

	submission := decode(t, submit(t, handler, asyncBody("run-6"), asyncHeaders("run-6")))
	runID := submission["run_id"].(string)

	// WORKER_MAX_ATTEMPTS bounds the retries, so the run ends terminally
	// failed rather than cycling through the queue forever.
	status := waitForStatus(t, handler, runID, "failed")
	if status["failure"] == nil {
		t.Fatalf("the run should carry a failure: %v", status)
	}
	failure := status["failure"].(map[string]any)
	if failure["retryable"] != false {
		t.Errorf("an attempt-exhausted failure must not be advertised as retryable: %v", failure)
	}
	if failure["code"] != "storage_unavailable" {
		t.Errorf("unexpected failure: %v", failure)
	}
	if len(fake.Rows()) != 0 {
		t.Errorf("nothing should have been persisted, got %d rows", len(fake.Rows()))
	}
}

// The referenced route works asynchronously too: the rule is still read from
// the Defense Generation row.
func TestAsyncReferencedRunCompilesTheRuleFromDatabricks(t *testing.T) {
	handler, fake := newTestServer(t)
	seedProofLoop(fake, provenSecRule)

	body := orchestrationBody("run-referenced-async")
	headers := map[string]string{
		"Idempotency-Key":  "run-referenced-async",
		"X-Correlation-ID": correlationID,
	}
	recorder := submit(t, handler, body, headers)
	if recorder.Code != http.StatusAccepted {
		t.Fatalf("submit = %d: %s", recorder.Code, recorder.Body.String())
	}
	runID := decode(t, recorder)["run_id"].(string)

	status := waitForStatus(t, handler, runID, "completed")
	if status["terminal_state"] != "translated" {
		t.Fatalf("terminal_state = %v", status["terminal_state"])
	}
	result := decode(t, get(t, handler, "/v1/control-translation-runs/"+runID+"/result"))
	candidate := result["structured_result"].(map[string]any)["primary_candidate"].(map[string]any)
	content := candidate["candidate_artifact"].(map[string]any)["content_ref"].(string)
	if !strings.Contains(content, "JANUS-CVE-2026-77392-Researcher") {
		t.Errorf("the async run did not compile the Defense Generation rule: %s", content)
	}
}
