import json
from pathlib import Path

from fastapi.testclient import TestClient

from control_translation import api as api_module
from control_translation.api import app
from control_translation.persistence import PersistenceError

client = TestClient(app)
DIRECT_BYPASS_EXAMPLE = (
    Path(__file__).resolve().parents[1]
    / "examples"
    / "request-direct-bypass-found.json"
)


def _request_body(target_technology: str, context_id: str) -> dict:
    return {
        "input": {
            "proven_pattern": {
                "proven_pattern_id": "proven-pattern:CVE-EXAMPLE:waf:3",
                "vulnerability_id": "CVE-EXAMPLE",
                "selected_control_class": "waf",
                "discriminator_id": "discriminator:CVE-EXAMPLE:cmd-param",
                "discriminator_description": (
                    "Blocks OGNL/EL expression syntax appearing in the "
                    "Content-Type header."
                ),
                "pattern_summary": (
                    "Block requests whose Content-Type header contains "
                    "OGNL/EL expression syntax."
                ),
                "proof_record_ids": [
                    "mitigation-check-result:CVE-EXAMPLE:3",
                    "bypass-validation-result:CVE-EXAMPLE:3",
                ],
            },
            "target_context": {
                "target_technology": target_technology,
                "target_policy_context_id": context_id,
            },
        }
    }


def test_health_ok():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_readiness_ok_for_fixture_mode():
    resp = client.get("/ready")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ready"}


def test_schema_names_capability_and_terminal_states():
    resp = client.get("/schema")
    assert resp.status_code == 200
    data = resp.json()
    assert data["capability"] == "control-translation"
    assert "translated" in data["terminal_states"]
    assert "akamai-waf" in data["supported_adapters"]
    assert data["inference"]["execution_mode"] == "fixture"


def test_inference_status_never_returns_credentials():
    resp = client.get("/inference")
    assert resp.status_code == 200
    data = resp.json()
    assert data["execution_mode"] == "fixture"
    assert "api_key" not in data


def test_invoke_returns_result_envelope():
    resp = client.post(
        "/invoke", json=_request_body("akamai-waf", "akamai-policy:example:rev-17")
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["terminal_state"] == "translated"
    assert data["structured_result"]["primary_candidate"] is not None
    assert data["inference"]["execution_mode"] == "fixture"
    assert data["inference"]["llm_invoked"] is False
    assert data["result_id"] == data["structured_result"]["result_id"]
    assert data["result_ref"]["result_id"] == data["result_id"]
    assert data["correlation_id"]


def test_direct_bypass_result_is_safely_declined_and_idempotent():
    body = json.loads(DIRECT_BYPASS_EXAMPLE.read_text())

    first = client.post("/invoke", json=body)
    second = client.post("/invoke", json=body)

    assert first.status_code == 200
    assert second.status_code == 200
    data = first.json()
    assert data["terminal_state"] == "scope-declined"
    assert data["status"] == "declined"
    assert data["request_id"] == body["result_id"]
    assert data["correlation_id"] == (
        body["input_bindings"]["prior_mitigation_check"]["correlation_id"]
    )
    assert data["run_id"] == second.json()["run_id"]
    assert data["structured_result"]["outcome_reason"]["code"] == (
        "bypass-found-requires-regeneration"
    )
    assert data["structured_result"]["primary_candidate"] is None
    assert data["structured_result"]["bypass_counterexample"] == (
        body["bypass_counterexample"]
    )
    assert data["inference"]["llm_invoked"] is False
    assert data["reference_bundle"]["bypass_validation"] == body["result_ref"]
    assert data["reference_bundle"]["mitigation_check"] == (
        body["input_bindings"]["prior_mitigation_check"]["result_ref"]
    )


def test_direct_bypass_result_conflicts_when_same_id_payload_changes():
    body = json.loads(DIRECT_BYPASS_EXAMPLE.read_text())
    first = client.post("/invoke", json=body)
    body["feedback"]["do_not_repeat"] += " Changed semantic input."

    second = client.post("/invoke", json=body)

    assert first.status_code == 200
    assert second.status_code == 409


def test_invoke_logs_lifecycle_and_sanitized_contracts(caplog):
    body = _request_body("akamai-waf", "akamai-policy:example:rev-17")
    body.update(
        {
            "request_id": "request-diagnostic-log",
            "correlation_id": "correlation-diagnostic-log",
            "idempotency_key": "raw-idempotency-secret",
        }
    )

    with caplog.at_level("INFO", logger="control_translation.api"):
        response = client.post("/invoke", json=body)

    assert response.status_code == 200
    candidate_content = response.json()["structured_result"]["primary_candidate"][
        "candidate_artifact"
    ]["content_ref"]
    assert "HTTP request started method=POST path=/invoke" in caplog.text
    assert "Invocation accepted request_id=request-diagnostic-log" in caplog.text
    assert "Invocation result source=capability" in caplog.text
    assert "Invocation durably persisted" in caplog.text
    assert "HTTP request completed method=POST path=/invoke status_code=200" in caplog.text
    assert '"idempotency_key":"[REDACTED]"' in caplog.text
    assert '"content_ref":"[REDACTED]"' in caplog.text
    assert "raw-idempotency-secret" not in caplog.text
    assert candidate_content not in caplog.text


def test_get_run_returns_recorded_result():
    invoke_resp = client.post(
        "/invoke", json=_request_body("akamai-waf", "akamai-policy:example:rev-17")
    )
    run_id = invoke_resp.json()["run_id"]

    run_resp = client.get(f"/runs/{run_id}")
    assert run_resp.status_code == 200
    assert run_resp.json()["run_id"] == run_id


def test_get_result_returns_durable_structured_result():
    invoke_resp = client.post(
        "/invoke", json=_request_body("akamai-waf", "akamai-policy:example:rev-17")
    )
    result_id = invoke_resp.json()["result_id"]

    result_resp = client.get(f"/v1/results/{result_id}")

    assert result_resp.status_code == 200
    assert result_resp.json()["result_id"] == result_id


def test_list_runs_returns_safe_summary_after_invocation():
    invoke_resp = client.post(
        "/invoke", json=_request_body("akamai-waf", "akamai-policy:example:rev-17")
    )
    assert invoke_resp.status_code == 200

    response = client.get("/v1/runs?limit=10&offset=0")

    assert response.status_code == 200
    data = response.json()
    assert data["total"] == 1
    assert data["has_more"] is False
    assert data["terminal_state_counts"] == {"translated": 1}
    assert data["items"][0]["run_id"] == invoke_resp.json()["run_id"]
    assert data["items"][0]["vulnerability_id"] == "CVE-EXAMPLE"
    assert data["items"][0]["target_technology"] == "akamai-waf"
    assert "structured_result" not in data["items"][0]
    assert "content_ref" not in response.text
    assert "request_json" not in response.text


def test_list_runs_validates_pagination_bounds():
    assert client.get("/v1/runs?limit=0").status_code == 422
    assert client.get("/v1/runs?limit=101").status_code == 422
    assert client.get("/v1/runs?offset=-1").status_code == 422


def test_list_runs_empty_page_is_well_formed():
    response = client.get("/v1/runs")

    assert response.status_code == 200
    assert response.json() == {
        "items": [],
        "total": 0,
        "limit": 25,
        "offset": 0,
        "has_more": False,
        "terminal_state_counts": {},
    }


def test_correlation_id_is_preserved():
    body = _request_body("akamai-waf", "akamai-policy:example:rev-17")
    body["correlation_id"] = "corr-api-test"

    response = client.post("/invoke", json=body)

    assert response.status_code == 200
    assert response.json()["correlation_id"] == "corr-api-test"


def test_request_id_is_generated_before_persistence(monkeypatch):
    captured = {}

    class CapturingRepository:
        def save_completed_run(self, request, *args, **kwargs):
            captured["request_id"] = request.request_id

    monkeypatch.setattr(api_module, "_REPOSITORY", CapturingRepository())

    response = client.post(
        "/invoke", json=_request_body("akamai-waf", "akamai-policy:example:rev-17")
    )

    assert response.status_code == 200
    assert captured["request_id"]


def test_caller_request_id_is_preserved_before_persistence(monkeypatch):
    captured = {}

    class CapturingRepository:
        def save_completed_run(self, request, *args, **kwargs):
            captured["request_id"] = request.request_id

    monkeypatch.setattr(api_module, "_REPOSITORY", CapturingRepository())
    body = _request_body("akamai-waf", "akamai-policy:example:rev-17")
    body["request_id"] = "request-provided-by-caller"

    response = client.post("/invoke", json=body)

    assert response.status_code == 200
    assert captured["request_id"] == "request-provided-by-caller"


def test_idempotent_retry_returns_the_original_result():
    body = _request_body("akamai-waf", "akamai-policy:example:rev-17")
    body["idempotency_key"] = "idem-api-test"

    first = client.post("/invoke", json=body)
    second = client.post("/invoke", json=body)

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["run_id"] == first.json()["run_id"]
    assert second.json()["result_id"] == first.json()["result_id"]


def test_idempotency_key_reuse_with_different_input_returns_conflict():
    first_body = _request_body("akamai-waf", "akamai-policy:example:rev-17")
    first_body["idempotency_key"] = "idem-conflict-test"
    second_body = _request_body("akamai-waf", "akamai-policy:example:rev-17")
    second_body["idempotency_key"] = "idem-conflict-test"
    second_body["input"]["proven_pattern"]["pattern_summary"] = "Different request"

    first = client.post("/invoke", json=first_body)
    second = client.post("/invoke", json=second_body)

    assert first.status_code == 200
    assert second.status_code == 409


def test_persistence_failure_returns_redacted_service_unavailable(
    monkeypatch, caplog
):
    class FailingRepository:
        def get_by_idempotency_key(self, key):
            return None

        def save_completed_run(self, *args, **kwargs):
            raise PersistenceError("Databricks principal lacks MODIFY permission")

    monkeypatch.setattr(api_module, "_REPOSITORY", FailingRepository())
    body = _request_body("akamai-waf", "akamai-policy:example:rev-17")
    body.update(
        {
            "request_id": "request-storage-failure",
            "correlation_id": "correlation-storage-failure",
            "idempotency_key": "secret-idempotency-value",
        }
    )

    with caplog.at_level("ERROR", logger="control_translation.api"):
        response = client.post("/invoke", json=body)

    assert response.status_code == 503
    detail = response.json()["detail"]
    assert detail["message"] == "Durable result storage is unavailable."
    assert detail["diagnostic"]["operation"] == "save-completed-run"
    assert detail["diagnostic"]["request_id"] == "request-storage-failure"
    assert detail["diagnostic"]["correlation_id"] == "correlation-storage-failure"
    assert detail["diagnostic"]["error_type"] == "PersistenceError"
    assert detail["diagnostic"]["error"] == (
        "Root-cause details are available only in server logs."
    )
    assert "MODIFY permission" not in response.text
    assert detail["diagnostic"]["server_traceback_logged"] is True
    assert "secret-idempotency-value" not in response.text
    assert "save-completed-run" in caplog.text
    assert "request-storage-failure" in caplog.text
    assert "correlation-storage-failure" in caplog.text
    assert "Databricks principal lacks MODIFY permission" in caplog.text
    assert "Traceback (most recent call last)" in caplog.text
    assert "secret-idempotency-value" not in caplog.text


def test_ui_diagnostic_never_returns_root_cause_text(monkeypatch):
    class FailingRepository:
        def save_completed_run(self, *args, **kwargs):
            cause = RuntimeError(
                "Bearer do-not-display; "
                "postgresql://user:password@internal.example/database; "
                "unstructured-secret-phrase"
            )
            raise PersistenceError("storage write failed") from cause

    monkeypatch.setattr(api_module, "_REPOSITORY", FailingRepository())

    response = client.post(
        "/invoke", json=_request_body("akamai-waf", "akamai-policy:example:rev-17")
    )

    diagnostic = response.json()["detail"]["diagnostic"]
    assert response.status_code == 503
    assert diagnostic["error_type"] == "RuntimeError"
    assert diagnostic["error"] == (
        "Root-cause details are available only in server logs."
    )
    assert "do-not-display" not in response.text
    assert "internal.example" not in response.text
    assert "unstructured-secret-phrase" not in response.text


def test_readiness_fails_when_storage_is_unavailable(monkeypatch):
    class UnavailableRepository:
        def healthcheck(self):
            return False

    monkeypatch.setattr(api_module, "_REPOSITORY", UnavailableRepository())

    response = client.get("/ready")

    assert response.status_code == 503
    assert response.json()["detail"]["storage"] == "unavailable"


def test_get_run_missing_returns_404():
    resp = client.get("/runs/does-not-exist")
    assert resp.status_code == 404
