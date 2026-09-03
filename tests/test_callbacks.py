from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient

from control_translation import api
from control_translation.api import app
from control_translation.callbacks import (
    CALLBACK_SIGNAL,
    CallbackDispatcher,
    CallbackHttpResponse,
    CallbackMetadata,
    CallbackTransportError,
    CallbackValidationError,
    callback_event_id,
    callback_metadata_from_headers,
)
from control_translation.contracts import InvokeRequestEnvelope
from control_translation.persistence import SQLiteRunRepository, normalized_request_digest

client = TestClient(app)

CALLBACK_HEADERS = {
    "X-Janus-Callback-URL": "https://orchestration.example.test/v1/capability-callbacks",
    "X-Janus-Callback-Workflow-ID": "janus-control-translation-abc123",
    "X-Janus-Callback-Signal": CALLBACK_SIGNAL,
}


def _request_body() -> dict:
    return {
        "request_id": "translation-request-123",
        "correlation_id": "correlation-123",
        "input": {
            "proven_pattern": {
                "proven_pattern_id": "proven-pattern:CVE-EXAMPLE:waf:3",
                "vulnerability_id": "CVE-EXAMPLE",
                "selected_control_class": "waf",
                "discriminator_id": "discriminator:CVE-EXAMPLE:cmd-param",
                "discriminator_description": "Blocks OGNL expression syntax.",
                "pattern_summary": "Block proven exploit traffic.",
                "proof_record_ids": [
                    "mitigation-check-result:CVE-EXAMPLE:3",
                    "bypass-validation-result:CVE-EXAMPLE:3",
                ],
            },
            "target_context": {
                "target_technology": "akamai-waf",
                "target_policy_context_id": "akamai-policy:example:rev-17",
            },
        },
        "provenance": {"caller": "orchestration", "source": "pytest"},
    }


def _submit_headers(*, callback: bool = True) -> dict[str, str]:
    headers = {
        "Idempotency-Key": "translation-request-123",
        "X-Correlation-ID": "correlation-123",
    }
    if callback:
        headers.update(CALLBACK_HEADERS)
    return headers


class SequenceHttpClient:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests: list[dict] = []

    def post_json(self, url, payload, *, token, timeout_seconds):
        self.requests.append(
            {
                "url": url,
                "payload": json.loads(payload),
                "token": token,
                "timeout_seconds": timeout_seconds,
            }
        )
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def _terminal_run(
    tmp_path=None,
    *,
    terminal_state: str = "translated",
    repository: SQLiteRunRepository | None = None,
) -> tuple[SQLiteRunRepository, str]:
    if repository is None:
        assert tmp_path is not None
        repository = SQLiteRunRepository(tmp_path / "callbacks.db")
    request = InvokeRequestEnvelope.model_validate(_request_body()).model_copy(
        update={"idempotency_key": "translation-request-123"}
    )
    created = repository.create_lifecycle_run(
        request,
        idempotency_key="translation-request-123",
        request_digest=normalized_request_digest(request),
        callback=CallbackMetadata(
            callback_url=CALLBACK_HEADERS["X-Janus-Callback-URL"],
            callback_workflow_id=CALLBACK_HEADERS["X-Janus-Callback-Workflow-ID"],
            callback_signal=CALLBACK_SIGNAL,
        ),
    )
    claimed = repository.claim_lifecycle_run(
        worker_id="callback-test-worker", lease_seconds=30, max_attempts=3
    )
    assert claimed is not None
    run_id = created.run.status.run_id
    result_id = f"result:{run_id}"
    completion = {
        "request_id": "translation-request-123",
        "correlation_id": "correlation-123",
        "run_id": run_id,
        "result_id": result_id,
        "terminal_state": terminal_state,
        "result_ref": {
            "system": "databricks",
            "catalog": "36889_janus_dev",
            "schema": "control_translation",
            "table": "control_translation_results",
            "key": result_id,
        },
        "evidence_refs": [],
        "content_sha256": "sha256:" + "0" * 64,
        "size_bytes": 1,
        "created_at": datetime.now(UTC).isoformat(),
    }
    assert repository.complete_lifecycle_run(
        run_id,
        worker_id="callback-test-worker",
        attempt_number=claimed.attempt_number,
        result={"run_id": run_id, "terminal_state": terminal_state},
        completion=completion,
        result_id=result_id,
        terminal_state=terminal_state,
    )
    return repository, run_id


def _delivery_row(repository: SQLiteRunRepository) -> sqlite3.Row:
    connection = sqlite3.connect(repository.database_path)
    connection.row_factory = sqlite3.Row
    try:
        row = connection.execute("SELECT * FROM callback_deliveries").fetchone()
    finally:
        connection.close()
    assert row is not None
    return row


def _accepted(event_id: str) -> CallbackHttpResponse:
    return CallbackHttpResponse(
        status_code=202,
        body=json.dumps({"event_id": event_id, "status": "accepted"}).encode(),
        headers={},
    )


def test_submit_accepts_and_persists_all_callback_headers():
    response = client.post(
        "/v1/control-translation-runs",
        json=_request_body(),
        headers=_submit_headers(),
    )

    assert response.status_code == 202
    stored = api._REPOSITORY.get_lifecycle_run(response.json()["run_id"])
    assert stored is not None
    assert stored.callback == CallbackMetadata(
        callback_url=CALLBACK_HEADERS["X-Janus-Callback-URL"],
        callback_workflow_id=CALLBACK_HEADERS["X-Janus-Callback-Workflow-ID"],
        callback_signal=CALLBACK_SIGNAL,
    )


def test_submit_without_callback_headers_remains_polling_only():
    response = client.post(
        "/v1/control-translation-runs",
        json=_request_body(),
        headers=_submit_headers(callback=False),
    )

    assert response.status_code == 202
    stored = api._REPOSITORY.get_lifecycle_run(response.json()["run_id"])
    assert stored is not None
    assert stored.callback is None


def test_idempotent_retry_can_attach_callback_metadata():
    first = client.post(
        "/v1/control-translation-runs",
        json=_request_body(),
        headers=_submit_headers(callback=False),
    )
    second = client.post(
        "/v1/control-translation-runs",
        json=_request_body(),
        headers=_submit_headers(),
    )

    assert first.status_code == second.status_code == 202
    assert first.json()["run_id"] == second.json()["run_id"]
    stored = api._REPOSITORY.get_lifecycle_run(second.json()["run_id"])
    assert stored is not None and stored.callback is not None


def test_submit_rejects_incomplete_callback_header_group():
    headers = _submit_headers(callback=False)
    headers["X-Janus-Callback-URL"] = CALLBACK_HEADERS["X-Janus-Callback-URL"]

    response = client.post(
        "/v1/control-translation-runs", json=_request_body(), headers=headers
    )

    assert response.status_code == 400
    assert response.json()["code"] == "invalid_callback_headers"


@pytest.mark.parametrize(
    "headers",
    [
        {**CALLBACK_HEADERS, "X-Janus-Callback-URL": "http://orchestration.test/callbacks"},
        {**CALLBACK_HEADERS, "X-Janus-Callback-Signal": "janus.capability-completion.v2"},
    ],
)
def test_callback_headers_require_https_and_exact_signal(headers):
    with pytest.raises(CallbackValidationError):
        callback_metadata_from_headers(headers)


def test_callback_hostname_allowlist_is_enforced():
    with pytest.raises(CallbackValidationError, match="allowlisted"):
        callback_metadata_from_headers(
            CALLBACK_HEADERS, allowed_hosts=("different.example.test",)
        )


@pytest.mark.parametrize("terminal_state", ["translated", "not-translatable"])
def test_completed_domain_outcomes_create_one_logical_callback(tmp_path, terminal_state):
    repository, run_id = _terminal_run(tmp_path, terminal_state=terminal_state)

    row = _delivery_row(repository)
    assert row["event_id"] == callback_event_id(run_id)
    assert row["terminal_status"] == "completed"
    with sqlite3.connect(repository.database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM callback_deliveries").fetchone()[0] == 1


def test_cancellation_creates_terminal_callback(tmp_path):
    repository = SQLiteRunRepository(tmp_path / "cancel.db")
    request = InvokeRequestEnvelope.model_validate(_request_body()).model_copy(
        update={"idempotency_key": "translation-request-123"}
    )
    created = repository.create_lifecycle_run(
        request,
        idempotency_key="translation-request-123",
        request_digest=normalized_request_digest(request),
        callback=CallbackMetadata(
            CALLBACK_HEADERS["X-Janus-Callback-URL"],
            CALLBACK_HEADERS["X-Janus-Callback-Workflow-ID"],
            CALLBACK_SIGNAL,
        ),
    )

    canceled = repository.cancel_lifecycle_run(created.run.status.run_id)

    assert canceled is not None and canceled.status.status == "canceled"
    assert _delivery_row(repository)["terminal_status"] == "canceled"


def test_callback_payload_has_only_required_identifiers(tmp_path):
    repository, run_id = _terminal_run(tmp_path)
    event_id = callback_event_id(run_id)
    http_client = SequenceHttpClient(_accepted(event_id))

    CallbackDispatcher(repository, token="shared-secret", http_client=http_client).deliver_due(
        now=datetime.now(UTC) + timedelta(seconds=1)
    )

    assert http_client.requests[0]["payload"] == {
        "workflow_id": "janus-control-translation-abc123",
        "wakeup": {
            "event_id": event_id,
            "capability": "control-translation",
            "request_id": "translation-request-123",
            "correlation_id": "correlation-123",
            "run_id": run_id,
        },
    }


@pytest.mark.parametrize("status_code", [429, 500, 502, 503, 504])
def test_retryable_responses_back_off_and_reuse_event_id(tmp_path, status_code):
    repository, run_id = _terminal_run(tmp_path)
    event_id = callback_event_id(run_id)
    http_client = SequenceHttpClient(
        CallbackHttpResponse(status_code=status_code, body=b"", headers={}),
        _accepted(event_id),
    )
    dispatcher = CallbackDispatcher(
        repository,
        token="shared-secret",
        http_client=http_client,
        jitter=lambda: 1.0,
    )
    first_attempt = datetime.now(UTC) + timedelta(seconds=1)

    dispatcher.deliver_due(now=first_attempt)
    retry_row = _delivery_row(repository)
    assert retry_row["delivery_status"] == "retry"
    assert datetime.fromisoformat(retry_row["next_attempt_at"]) == first_attempt + timedelta(seconds=5)

    dispatcher.deliver_due(now=first_attempt + timedelta(seconds=5))
    assert [request["payload"]["wakeup"]["event_id"] for request in http_client.requests] == [
        event_id,
        event_id,
    ]
    assert _delivery_row(repository)["delivery_status"] == "delivered"


def test_retry_after_is_honored(tmp_path):
    repository, _ = _terminal_run(tmp_path)
    now = datetime.now(UTC) + timedelta(seconds=1)
    dispatcher = CallbackDispatcher(
        repository,
        token="shared-secret",
        http_client=SequenceHttpClient(
            CallbackHttpResponse(status_code=429, body=b"", headers={"Retry-After": "37"})
        ),
        jitter=lambda: 1.0,
    )

    dispatcher.deliver_due(now=now)

    assert datetime.fromisoformat(_delivery_row(repository)["next_attempt_at"]) == now + timedelta(seconds=37)


def test_202_marks_delivery_complete(tmp_path):
    repository, run_id = _terminal_run(tmp_path)
    dispatcher = CallbackDispatcher(
        repository,
        token="shared-secret",
        http_client=SequenceHttpClient(_accepted(callback_event_id(run_id))),
    )

    dispatcher.deliver_due(now=datetime.now(UTC) + timedelta(seconds=1))

    assert _delivery_row(repository)["delivery_status"] == "delivered"


def test_401_alerts_without_exposing_token_or_canonical_result(tmp_path, caplog):
    repository, run_id = _terminal_run(tmp_path)
    dispatcher = CallbackDispatcher(
        repository,
        token="do-not-log-this-token",
        http_client=SequenceHttpClient(
            CallbackHttpResponse(status_code=401, body=b"invalid", headers={})
        ),
    )

    with caplog.at_level("INFO", logger="control_translation.callbacks"):
        dispatcher.deliver_due(now=datetime.now(UTC) + timedelta(seconds=1))

    assert _delivery_row(repository)["delivery_status"] == "configuration-failed"
    assert repository.get_lifecycle_run(run_id).status.status == "completed"
    assert repository.get_lifecycle_result(run_id)["terminal_state"] == "translated"
    assert "configuration alert" in caplog.text
    assert "do-not-log-this-token" not in caplog.text


def test_network_failure_retries_without_hiding_status_or_result(tmp_path):
    repository, run_id = _terminal_run(tmp_path)
    dispatcher = CallbackDispatcher(
        repository,
        token="shared-secret",
        http_client=SequenceHttpClient(CallbackTransportError("dns-failure")),
        jitter=lambda: 1.0,
    )

    dispatcher.deliver_due(now=datetime.now(UTC) + timedelta(seconds=1))

    assert _delivery_row(repository)["delivery_status"] == "retry"
    assert repository.get_lifecycle_run(run_id).status.status == "completed"
    assert repository.get_lifecycle_result(run_id) is not None


def test_callback_failure_keeps_http_status_and_result_available(
    isolated_api_repository,
):
    repository, run_id = _terminal_run(repository=isolated_api_repository)
    dispatcher = CallbackDispatcher(
        repository,
        token="shared-secret",
        http_client=SequenceHttpClient(
            CallbackHttpResponse(status_code=401, body=b"invalid", headers={})
        ),
    )

    dispatcher.deliver_due(now=datetime.now(UTC) + timedelta(seconds=1))

    status_response = client.get(f"/v1/control-translation-runs/{run_id}")
    result_response = client.get(f"/v1/control-translation-runs/{run_id}/result")
    assert status_response.status_code == 200
    assert status_response.json()["status"] == "completed"
    assert result_response.status_code == 200
    assert result_response.json()["terminal_state"] == "translated"


def test_duplicate_dispatch_does_not_change_canonical_result(tmp_path):
    repository, run_id = _terminal_run(tmp_path)
    http_client = SequenceHttpClient(_accepted(callback_event_id(run_id)))
    dispatcher = CallbackDispatcher(repository, token="shared-secret", http_client=http_client)
    now = datetime.now(UTC) + timedelta(seconds=1)
    original_result = repository.get_lifecycle_result(run_id)

    dispatcher.deliver_due(now=now)
    assert dispatcher.deliver_due(now=now + timedelta(hours=1)) == 0

    assert len(http_client.requests) == 1
    assert repository.get_lifecycle_result(run_id) == original_result


def test_terminal_state_and_result_exist_before_http_delivery(tmp_path):
    repository, run_id = _terminal_run(tmp_path)

    class InspectingClient:
        def post_json(self, url, payload, *, token, timeout_seconds):
            assert repository.get_lifecycle_run(run_id).status.status == "completed"
            assert repository.get_lifecycle_result(run_id) is not None
            return _accepted(callback_event_id(run_id))

    CallbackDispatcher(
        repository, token="shared-secret", http_client=InspectingClient()
    ).deliver_due(now=datetime.now(UTC) + timedelta(seconds=1))


def test_missing_token_logs_configuration_error_and_polling_stays_available(
    monkeypatch, caplog
):
    monkeypatch.setattr(api._SETTINGS, "capability_callback_token", None)

    with caplog.at_level("INFO", logger="control_translation.api"):
        response = client.post(
            "/v1/control-translation-runs",
            json=_request_body(),
            headers=_submit_headers(),
        )

    assert response.status_code == 202
    assert client.get(response.json()["status_url"]).status_code == 200
    assert "missing-callback-token" in caplog.text
    assert "Callback metadata accepted" in caplog.text
