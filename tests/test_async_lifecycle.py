from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path
from threading import Event
from time import monotonic

import pytest
from fastapi.testclient import TestClient

from control_translation import api as api_module
from control_translation.api import app
from control_translation.cancellation import check_cancelled
from control_translation.config import Settings
from control_translation.contracts import (
    CapabilityRunStatus,
    InvokeRequestEnvelope,
    RunFailure,
)
from control_translation.lifecycle import LifecycleWorker
from control_translation.persistence import (
    PersistenceError,
    SplitRunRepository,
    SQLiteRunRepository,
    canonical_result_bytes,
    normalized_request_digest,
)

client = TestClient(app)


class _CountingResultSink(SQLiteRunRepository):
    """SQLite-backed stand-in for an idempotent external immutable sink."""

    def __init__(self, database_path: str | Path):
        super().__init__(database_path)
        self.publish_calls = 0
        self.after_publish: Callable[[], None] | None = None

    def save_completed_run(self, *args, **kwargs):
        self.publish_calls += 1
        super().save_completed_run(*args, **kwargs)
        if self.after_publish is not None:
            self.after_publish()


def _body(summary: str = "Block proven exploit traffic.") -> dict:
    return {
        "request_id": "request-async-test",
        "correlation_id": "correlation-async-test",
        "input": {
            "proven_pattern": {
                "proven_pattern_id": "proven-pattern:CVE-EXAMPLE:waf:3",
                "vulnerability_id": "CVE-EXAMPLE",
                "selected_control_class": "waf",
                "discriminator_id": "discriminator:CVE-EXAMPLE:cmd-param",
                "discriminator_description": "Blocks OGNL expression syntax.",
                "pattern_summary": summary,
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


def _headers() -> dict[str, str]:
    return {
        "Idempotency-Key": "request-async-test",
        "X-Correlation-ID": "correlation-async-test",
    }


def _wait_for_terminal(run_id: str) -> dict:
    deadline = monotonic() + 5
    while monotonic() < deadline:
        response = client.get(f"/v1/control-translation-runs/{run_id}")
        assert response.status_code == 200
        status = response.json()
        if status["status"] in {"completed", "failed", "canceled"}:
            return status
    raise AssertionError("run did not become terminal")


def test_submit_is_async_and_result_is_immutable():
    started = monotonic()
    response = client.post(
        "/v1/control-translation-runs", json=_body(), headers=_headers()
    )

    assert response.status_code == 202
    assert monotonic() - started < 2
    submission = response.json()
    run_id = submission["run_id"]
    terminal = _wait_for_terminal(run_id)
    assert terminal["status"] == "completed"
    assert terminal["completion"]["result_ref"]["key"] == terminal["result_id"]
    assert terminal["completion"]["content_sha256"].startswith("sha256:")

    first = client.get(submission["result_url"])
    second = client.get(submission["result_url"])
    assert first.status_code == 200
    assert second.json() == first.json()
    assert first.json()["contract_id"] == "control-translation-result@1.0"
    assert first.json()["run_id"] == run_id
    assert first.json()["primary_candidate"]["candidate_id"]
    content_ref = first.json()["primary_candidate"]["content_ref"]
    assert content_ref.startswith(
        "databricks://36889_janus_dev/control_translation/"
        "control_translation_results/result_json?result_id="
    )
    assert content_ref.endswith("#/artifacts/primary/content")
    assert "/v1/results/" not in content_ref
    artifact = first.json()["artifacts"]["primary"]
    assert artifact["content_hash"] == first.json()["primary_candidate"]["content_hash"]
    assert artifact["media_type"] == "application/json"
    assert sha256(artifact["content"].encode("utf-8")).hexdigest() == artifact[
        "content_hash"
    ].removeprefix("sha256:")
    metadata = first.json()["primary_candidate"]["candidate_metadata"]
    assert metadata == artifact["candidate_metadata"]
    assert metadata["syntax_profile"] == {
        "id": "janus-akamai-like-custom-rule-demo@1",
        "family": "akamai-like-custom-rule",
        "validation_level": "shape-only",
        "deployment_ready": False,
    }
    assert metadata["recommended_policy_binding"]["action"] == "deny"
    assert first.json()["inference"]["proposal_source"]
    assert first.json()["inference"]["llm_invoked"] is False
    assert first.json()["result_ref"]["key"] == first.json()["result_id"]
    result = first.json()
    digest = result.pop("content_sha256")
    size_bytes = result.pop("size_bytes")
    content = canonical_result_bytes(result)
    assert digest == f"sha256:{sha256(content).hexdigest()}"
    assert size_bytes == len(content)
    assert terminal["completion"]["content_sha256"] == digest
    assert terminal["completion"]["size_bytes"] == size_bytes


def test_identical_retry_reuses_run_and_conflict_is_structured():
    first = client.post(
        "/v1/control-translation-runs", json=_body(), headers=_headers()
    )
    second = client.post(
        "/v1/control-translation-runs", json=_body(), headers=_headers()
    )
    conflict = client.post(
        "/v1/control-translation-runs",
        json=_body("Semantically different input."),
        headers=_headers(),
    )

    assert first.status_code == 202
    assert second.status_code in {200, 202}
    assert second.json()["run_id"] == first.json()["run_id"]
    assert conflict.status_code == 409
    assert conflict.json() == {
        "code": "idempotency_conflict",
        "detail": "Idempotency-Key is already bound to a different normalized request.",
        "retryable": False,
    }


def test_headers_must_align_with_caller_identity():
    headers = _headers()
    headers["X-Correlation-ID"] = "different"

    response = client.post(
        "/v1/control-translation-runs", json=_body(), headers=headers
    )

    assert response.status_code == 400
    assert response.json()["code"] == "correlation_identity_mismatch"
    assert response.json()["retryable"] is False


def test_content_type_is_required():
    response = client.post(
        "/v1/control-translation-runs",
        content=json.dumps(_body()),
        headers={**_headers(), "Content-Type": "text/plain"},
    )

    assert response.status_code == 400
    assert response.json()["code"] == "invalid_content_type"


def test_terminal_log_metric_contains_all_identities(caplog):
    with caplog.at_level("INFO", logger="control_translation.lifecycle"):
        response = client.post(
            "/v1/control-translation-runs", json=_body(), headers=_headers()
        )
        terminal = _wait_for_terminal(response.json()["run_id"])

    assert "metric=control_translation_lifecycle_terminal_total" in caplog.text
    assert f"request_id={terminal['request_id']}" in caplog.text
    assert f"correlation_id={terminal['correlation_id']}" in caplog.text
    assert f"run_id={terminal['run_id']}" in caplog.text
    assert f"result_id={terminal['result_id']}" in caplog.text


def test_body_callback_is_rejected_in_favor_of_headers():
    body = _body()
    body["callback"] = {
        "url": "https://orchestration.example/v1/capability-run-events",
        "event_contract_id": "capability-run-event@1.0",
    }

    response = client.post(
        "/v1/control-translation-runs", json=body, headers=_headers()
    )

    assert response.status_code == 400
    assert response.json() == {
        "code": "callback_not_supported",
        "detail": "Body callbacks are not supported; use the X-Janus-Callback-* headers.",
        "retryable": False,
    }


def test_storage_errors_are_root_envelopes(monkeypatch):
    def fail(_: str):
        raise PersistenceError("database path and secret details")

    monkeypatch.setattr(api_module._REPOSITORY, "get_lifecycle_run", fail)

    response = client.get("/v1/control-translation-runs/missing")

    assert response.status_code == 503
    body = response.json()
    assert body["code"] == "storage_unavailable"
    assert body["detail"] == "Durable result storage is unavailable."
    assert body["retryable"] is True
    assert "database path and secret details" not in body["detail"]


def test_result_is_not_available_before_terminal(monkeypatch):
    api_module._LIFECYCLE_WORKER.stop()
    monkeypatch.setattr(api_module._LIFECYCLE_WORKER, "wake", lambda: None)
    response = client.post(
        "/v1/control-translation-runs", json=_body(), headers=_headers()
    )
    run_id = response.json()["run_id"]

    result = client.get(f"/v1/control-translation-runs/{run_id}/result")

    assert result.status_code == 409
    assert result.json()["code"] == "run_not_terminal"


def test_queued_cancellation_is_idempotent(monkeypatch):
    api_module._LIFECYCLE_WORKER.stop()
    monkeypatch.setattr(api_module._LIFECYCLE_WORKER, "wake", lambda: None)
    response = client.post(
        "/v1/control-translation-runs", json=_body(), headers=_headers()
    )
    run_id = response.json()["run_id"]

    first = client.post(f"/v1/control-translation-runs/{run_id}/cancel")
    second = client.post(f"/v1/control-translation-runs/{run_id}/cancel")

    assert first.status_code == 200
    assert first.json()["status"] == "canceled"
    assert second.json() == first.json()

    terminal_result = client.get(
        f"/v1/control-translation-runs/{run_id}/result"
    )
    assert terminal_result.status_code == 200
    assert terminal_result.json() == first.json()


def test_failed_run_result_returns_terminal_status_envelope(tmp_path, monkeypatch):
    repository = SQLiteRunRepository(tmp_path / "failed-result.db")
    monkeypatch.setattr(api_module, "_REPOSITORY", repository)
    request = InvokeRequestEnvelope.model_validate(_body())
    created = repository.create_lifecycle_run(
        request,
        idempotency_key=request.request_id or "",
        request_digest=normalized_request_digest(request),
    )
    claimed = repository.claim_lifecycle_run(
        worker_id="failed-worker", lease_seconds=30, max_attempts=3
    )
    assert claimed is not None
    assert repository.fail_lifecycle_run(
        created.run.status.run_id,
        worker_id="failed-worker",
        attempt_number=claimed.attempt_number,
        failure=RunFailure(
            code="provider_failed", detail="Provider failed.", retryable=True
        ),
    )

    response = client.get(
        f"/v1/control-translation-runs/{created.run.status.run_id}/result"
    )

    assert response.status_code == 200
    assert response.json()["contract_id"] == "capability-run-status@1.0"
    assert response.json()["status"] == "failed"
    assert response.json()["failure"]["code"] == "provider_failed"


def test_status_survives_repository_restart(isolated_api_repository):
    response = client.post(
        "/v1/control-translation-runs", json=_body(), headers=_headers()
    )
    run_id = response.json()["run_id"]
    expected = _wait_for_terminal(run_id)

    restarted = SQLiteRunRepository(isolated_api_repository.database_path)
    actual = restarted.get_lifecycle_run(run_id)

    assert actual is not None
    assert actual.status == CapabilityRunStatus.model_validate(expected)


def test_sqlite_lifecycle_uses_delete_journal(isolated_api_repository):
    with sqlite3.connect(isolated_api_repository.database_path) as connection:
        journal_mode = connection.execute("PRAGMA journal_mode").fetchone()[0]

    assert journal_mode == "delete"


def test_expired_worker_lease_is_recovered_with_bounded_attempts(tmp_path):
    repository = SQLiteRunRepository(tmp_path / "lease.db")
    request = InvokeRequestEnvelope.model_validate(_body())
    digest = normalized_request_digest(request)
    created = repository.create_lifecycle_run(
        request,
        idempotency_key=request.request_id or "",
        request_digest=digest,
    )
    first = repository.claim_lifecycle_run(
        worker_id="worker-one", lease_seconds=30, max_attempts=2
    )
    assert first is not None
    with sqlite3.connect(repository.database_path) as connection:
        connection.execute(
            "UPDATE capability_run_lifecycle SET lease_expires_at = '2000-01-01T00:00:00+00:00' WHERE run_id = ?",
            (created.run.status.run_id,),
        )
    recovered = repository.claim_lifecycle_run(
        worker_id="worker-two", lease_seconds=30, max_attempts=2
    )
    assert recovered is not None
    assert recovered.attempt_number == 2
    with sqlite3.connect(repository.database_path) as connection:
        connection.execute(
            "UPDATE capability_run_lifecycle SET lease_expires_at = '2000-01-01T00:00:00+00:00' WHERE run_id = ?",
            (created.run.status.run_id,),
        )
    assert repository.claim_lifecycle_run(
        worker_id="worker-three", lease_seconds=30, max_attempts=2
    ) is None
    failed = repository.get_lifecycle_run(created.run.status.run_id)
    assert failed is not None
    assert failed.status.status == "failed"
    assert failed.status.failure is not None
    assert failed.status.failure.code == "worker_attempts_exhausted"
    assert failed.status.request_id == request.request_id
    assert failed.status.correlation_id == request.correlation_id
    assert failed.status.run_id == created.run.status.run_id
    assert failed.status.created_at is not None
    assert failed.status.updated_at is not None
    assert failed.status.completed_at is not None


def test_running_cancellation_is_atomically_finalized(tmp_path):
    repository = SQLiteRunRepository(tmp_path / "cancel-running.db")
    request = InvokeRequestEnvelope.model_validate(_body())
    created = repository.create_lifecycle_run(
        request,
        idempotency_key=request.request_id or "",
        request_digest=normalized_request_digest(request),
    )
    claimed = repository.claim_lifecycle_run(
        worker_id="worker-one", lease_seconds=30, max_attempts=3
    )
    assert claimed is not None

    requested = repository.cancel_lifecycle_run(created.run.status.run_id)
    stale_failure = repository.fail_lifecycle_run(
        created.run.status.run_id,
        worker_id="worker-one",
        attempt_number=claimed.attempt_number,
        failure=RunFailure(
            code="canceled", detail="Cancellation completed.", retryable=False
        ),
    )
    current = repository.cancel_lifecycle_run(created.run.status.run_id)

    assert requested is not None
    assert requested.cancel_requested is True
    assert requested.status.status == "canceled"
    assert requested.worker_id is None
    assert stale_failure is False
    assert current is not None
    assert current.status.status == "canceled"
    assert current.status.failure is None


def test_executing_operation_observes_cancellation_without_publishing(monkeypatch):
    started = Event()
    observed = Event()
    returned = Event()

    class BlockingDoer:
        def propose(self, *, cancellation_signal=None, **kwargs):
            assert cancellation_signal is not None
            started.set()
            try:
                assert cancellation_signal.wait(5), "provider did not receive cancellation"
                observed.set()
                check_cancelled(cancellation_signal)
            finally:
                returned.set()

    monkeypatch.setattr(
        "control_translation.capability.build_translation_doer",
        lambda settings: BlockingDoer(),
    )
    submission = client.post(
        "/v1/control-translation-runs", json=_body(), headers=_headers()
    )
    assert submission.status_code == 202
    run_id = submission.json()["run_id"]
    assert started.wait(2), "translation did not start"

    cancel_started = monotonic()
    canceled = client.post(f"/v1/control-translation-runs/{run_id}/cancel")
    cancel_elapsed = monotonic() - cancel_started

    assert canceled.status_code == 200
    assert canceled.json()["status"] == "canceled"
    assert cancel_elapsed < 1
    assert observed.wait(2), "executing provider did not observe cancellation"
    assert returned.wait(2), "canceled translation did not return"
    terminal_result = client.get(
        f"/v1/control-translation-runs/{run_id}/result"
    )
    assert terminal_result.status_code == 200
    assert terminal_result.json()["status"] == "canceled"
    assert api_module._REPOSITORY.get_run(run_id) is None
    assert api_module._REPOSITORY.get_lifecycle_result(run_id) is None


def test_stale_attempt_is_fenced_even_when_worker_id_is_reused(tmp_path):
    repository = SQLiteRunRepository(tmp_path / "fencing.db")
    request = InvokeRequestEnvelope.model_validate(_body())
    created = repository.create_lifecycle_run(
        request,
        idempotency_key=request.request_id or "",
        request_digest=normalized_request_digest(request),
    )
    first = repository.claim_lifecycle_run(
        worker_id="reused-worker", lease_seconds=30, max_attempts=3
    )
    assert first is not None
    with sqlite3.connect(repository.database_path) as connection:
        connection.execute(
            "UPDATE capability_run_lifecycle SET lease_expires_at = '2000-01-01T00:00:00+00:00' WHERE run_id = ?",
            (created.run.status.run_id,),
        )
    second = repository.claim_lifecycle_run(
        worker_id="reused-worker", lease_seconds=30, max_attempts=3
    )
    assert second is not None
    assert second.attempt_number == first.attempt_number + 1

    assert repository.heartbeat_lifecycle_run(
        created.run.status.run_id,
        worker_id="reused-worker",
        attempt_number=first.attempt_number,
        lease_seconds=30,
    ) is False
    assert repository.complete_lifecycle_run(
        created.run.status.run_id,
        worker_id="reused-worker",
        attempt_number=first.attempt_number,
        result={"stale": True},
        completion={"stale": True},
        result_id="stale-result",
        terminal_state="translated",
    ) is False
    current = repository.get_lifecycle_run(created.run.status.run_id)
    assert current is not None
    assert current.status.status == "running"
    assert current.attempt_number == second.attempt_number


def test_running_cancellation_suppresses_result_persistence(tmp_path, monkeypatch):
    repository = SQLiteRunRepository(tmp_path / "cancel-race.db")
    request = InvokeRequestEnvelope.model_validate(_body())
    created = repository.create_lifecycle_run(
        request,
        idempotency_key=request.request_id or "",
        request_digest=normalized_request_digest(request),
    )
    settings = Settings(
        run_mode="fixture",
        model_provider="none",
        database_path=str(repository.database_path),
        worker_heartbeat_seconds=1,
        worker_lease_seconds=30,
    )
    worker = LifecycleWorker(lambda: repository, lambda: None, settings)
    claimed = repository.claim_lifecycle_run(
        worker_id=worker._worker_id, lease_seconds=30, max_attempts=3
    )
    assert claimed is not None
    generated = api_module.capability.invoke_envelope(
        request, resolver=None, settings=settings
    )

    def cancel_during_translation(*args, **kwargs):
        repository.cancel_lifecycle_run(created.run.status.run_id)
        return generated

    monkeypatch.setattr(
        "control_translation.lifecycle.capability.invoke_envelope",
        cancel_during_translation,
    )

    worker._process(claimed, Event())

    current = repository.get_lifecycle_run(created.run.status.run_id)
    assert current is not None
    assert current.status.status == "canceled"
    assert repository.get_run(created.run.status.run_id) is None


def _split_worker_run(tmp_path, name: str):
    lifecycle = SQLiteRunRepository(tmp_path / f"{name}-lifecycle.db")
    sink = _CountingResultSink(tmp_path / f"{name}-sink.db")
    repository = SplitRunRepository(lifecycle, sink)
    request = InvokeRequestEnvelope.model_validate(_body())
    created = repository.create_lifecycle_run(
        request,
        idempotency_key=request.request_id or "",
        request_digest=normalized_request_digest(request),
    )
    settings = Settings(
        run_mode="fixture",
        model_provider="none",
        database_path=str(lifecycle.database_path),
        worker_heartbeat_seconds=1,
        worker_lease_seconds=30,
    )
    worker = LifecycleWorker(lambda: repository, lambda: None, settings)
    claimed = repository.claim_lifecycle_run(
        worker_id=worker._worker_id,
        lease_seconds=30,
        max_attempts=3,
    )
    assert claimed is not None
    return lifecycle, sink, repository, worker, claimed, created.run.status.run_id


def test_crash_after_external_publish_leaves_durable_pending_publication(
    tmp_path, monkeypatch
):
    lifecycle, sink, repository, worker, claimed, run_id = _split_worker_run(
        tmp_path, "crash-window"
    )

    def crash_before_finalize(*args, **kwargs):
        raise RuntimeError("simulated process crash before SQLite finalize")

    monkeypatch.setattr(repository, "complete_lifecycle_run", crash_before_finalize)

    with pytest.raises(RuntimeError, match="simulated process crash"):
        worker._process(claimed, Event())

    pending = lifecycle.get_lifecycle_run(run_id)
    prepared = lifecycle.get_prepared_publication(run_id)
    assert sink.publish_calls == 1
    assert sink.get_run(run_id) is not None
    assert pending is not None
    assert pending.status.status == "running"
    assert pending.publication_state == "publication-pending"
    assert prepared is not None
    assert prepared.canonical_result["result_id"] == prepared.result_id
    assert prepared.completion["content_sha256"] == prepared.canonical_result["content_sha256"]


def test_recovery_reuses_published_row_without_regenerating(tmp_path, monkeypatch):
    lifecycle, sink, repository, worker, claimed, run_id = _split_worker_run(
        tmp_path, "recovery"
    )
    original_complete = repository.complete_lifecycle_run
    monkeypatch.setattr(
        repository,
        "complete_lifecycle_run",
        lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("crash")),
    )
    with pytest.raises(RuntimeError, match="crash"):
        worker._process(claimed, Event())
    first_prepared = lifecycle.get_prepared_publication(run_id)
    assert first_prepared is not None

    with sqlite3.connect(lifecycle.database_path) as connection:
        connection.execute(
            "UPDATE capability_run_lifecycle SET lease_expires_at = '2000-01-01T00:00:00+00:00' WHERE run_id = ?",
            (run_id,),
        )
    recovered_worker = LifecycleWorker(lambda: repository, lambda: None, worker._settings)
    recovered = repository.claim_lifecycle_run(
        worker_id=recovered_worker._worker_id,
        lease_seconds=30,
        max_attempts=3,
    )
    assert recovered is not None
    monkeypatch.setattr(repository, "complete_lifecycle_run", original_complete)
    monkeypatch.setattr(
        "control_translation.lifecycle.capability.invoke_envelope",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("recovery regenerated the result")
        ),
    )

    recovered_worker._process(recovered, Event())

    terminal = lifecycle.get_lifecycle_run(run_id)
    recovered_prepared = lifecycle.get_prepared_publication(run_id)
    assert sink.publish_calls == 2
    assert terminal is not None
    assert terminal.status.status == "completed"
    assert terminal.publication_state == "published"
    assert recovered_prepared is not None
    assert recovered_prepared.result_envelope == first_prepared.result_envelope
    assert recovered_prepared.canonical_result == first_prepared.canonical_result
    assert recovered_prepared.completion == first_prepared.completion


def test_cancel_race_respects_publication_cutoff(tmp_path, monkeypatch):
    lifecycle, sink, repository, worker, claimed, run_id = _split_worker_run(
        tmp_path, "cancel-before"
    )
    original_begin = repository.begin_lifecycle_publication

    def cancel_before_publish(*args, **kwargs):
        lifecycle.cancel_lifecycle_run(run_id)
        return original_begin(*args, **kwargs)

    monkeypatch.setattr(repository, "begin_lifecycle_publication", cancel_before_publish)
    worker._process(claimed, Event())
    canceled = lifecycle.get_lifecycle_run(run_id)
    assert canceled is not None
    assert canceled.status.status == "canceled"
    assert sink.publish_calls == 0

    lifecycle2, sink2, _repository2, worker2, claimed2, run_id2 = _split_worker_run(
        tmp_path, "cancel-after"
    )
    sink2.after_publish = lambda: lifecycle2.cancel_lifecycle_run(run_id2)

    worker2._process(claimed2, Event())

    completed = lifecycle2.get_lifecycle_run(run_id2)
    assert sink2.publish_calls == 1
    assert completed is not None
    assert completed.cancel_requested is True
    assert completed.status.status == "completed"
    assert completed.publication_state == "published"
    assert lifecycle2.get_lifecycle_result(run_id2) is not None
