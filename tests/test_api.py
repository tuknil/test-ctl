from fastapi.testclient import TestClient

from control_translation.api import app


client = TestClient(app)


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
                "proof_record_ids": ["mitigation-check-result:CVE-EXAMPLE:3"],
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


def test_schema_names_capability_and_terminal_states():
    resp = client.get("/schema")
    assert resp.status_code == 200
    data = resp.json()
    assert data["capability"] == "control-translation"
    assert "translated" in data["terminal_states"]
    assert "akamai-waf" in data["supported_adapters"]


def test_invoke_returns_result_envelope():
    resp = client.post(
        "/invoke", json=_request_body("akamai-waf", "akamai-policy:example:rev-17")
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["terminal_state"] == "translated"
    assert data["structured_result"]["primary_candidate"] is not None


def test_get_run_returns_recorded_result():
    invoke_resp = client.post(
        "/invoke", json=_request_body("akamai-waf", "akamai-policy:example:rev-17")
    )
    run_id = invoke_resp.json()["run_id"]

    run_resp = client.get(f"/runs/{run_id}")
    assert run_resp.status_code == 200
    assert run_resp.json()["run_id"] == run_id


def test_get_run_missing_returns_404():
    resp = client.get("/runs/does-not-exist")
    assert resp.status_code == 404
