from __future__ import annotations

import sqlite3
from datetime import UTC, datetime

from control_translation import capability
from control_translation.config import Settings
from control_translation.contracts import (
    ControlTranslationRequest,
    InvokeRequestEnvelope,
    TargetContext,
)
from control_translation.persistence import SQLiteRunRepository, canonical_request_hash
from control_translation.providers.fixtures import get_fixture_pattern


def _invocation() -> InvokeRequestEnvelope:
    pattern = get_fixture_pattern("proven-pattern:CVE-EXAMPLE:waf:3")
    assert pattern is not None
    return InvokeRequestEnvelope(
        input=ControlTranslationRequest(
            proven_pattern=pattern,
            target_context=TargetContext(
                target_technology="akamai-waf",
                target_policy_context_id="akamai-policy:example:rev-17",
            ),
        ),
        request_id="request-persistence-test",
        correlation_id="correlation-persistence-test",
        idempotency_key="idempotency-persistence-test",
    )


def _result(envelope: InvokeRequestEnvelope):
    return capability.invoke(
        envelope.input,
        settings=Settings(run_mode="fixture", model_provider="none"),
        correlation_id=envelope.correlation_id,
    )


def test_schema_initialization_is_idempotent(tmp_path):
    database_path = tmp_path / "runs.db"
    repository = SQLiteRunRepository(database_path)

    repository.initialize()
    repository.initialize()

    with sqlite3.connect(database_path) as connection:
        migrations = connection.execute(
            "SELECT version, name FROM schema_migrations"
        ).fetchall()
    assert migrations == [
        (1, "initial_persistence_schema"),
        (2, "async_capability_lifecycle"),
        (3, "durable_result_publication_outbox"),
    ]


def test_complete_result_artifact_and_evidence_are_persisted(tmp_path):
    database_path = tmp_path / "runs.db"
    repository = SQLiteRunRepository(database_path)
    request = _invocation()
    result = _result(request)

    repository.save_completed_run(
        request,
        result,
        request_hash=canonical_request_hash(request),
        started_at=datetime.now(UTC),
    )

    assert repository.get_run(result.run_id) == result
    assert repository.get_result(result.result_id) == result

    with sqlite3.connect(database_path) as connection:
        run_count = connection.execute("SELECT COUNT(*) FROM capability_runs").fetchone()[0]
        payload_count = connection.execute(
            "SELECT COUNT(*) FROM invocation_payloads"
        ).fetchone()[0]
        artifact_count = connection.execute(
            "SELECT COUNT(*) FROM result_artifacts"
        ).fetchone()[0]
        evidence_count = connection.execute(
            "SELECT COUNT(*) FROM evidence_references"
        ).fetchone()[0]
        stored_content = connection.execute(
            "SELECT content FROM result_artifacts"
        ).fetchone()[0]

    assert run_count == 1
    assert payload_count == 1
    assert artifact_count == 1
    assert evidence_count >= 2
    assert stored_content == (
        result.structured_result.primary_candidate.candidate_artifact.content_ref
    )


def test_result_survives_repository_restart(tmp_path):
    database_path = tmp_path / "runs.db"
    request = _invocation()
    result = _result(request)
    first_repository = SQLiteRunRepository(database_path)
    first_repository.save_completed_run(
        request,
        result,
        request_hash=canonical_request_hash(request),
        started_at=datetime.now(UTC),
    )

    restarted_repository = SQLiteRunRepository(database_path)

    assert restarted_repository.get_run(result.run_id) == result
    assert restarted_repository.get_result(result.result_id) == result


def test_idempotency_record_round_trips(tmp_path):
    repository = SQLiteRunRepository(tmp_path / "runs.db")
    request = _invocation()
    result = _result(request)
    request_hash = canonical_request_hash(request)
    repository.save_completed_run(
        request,
        result,
        request_hash=request_hash,
        started_at=datetime.now(UTC),
    )

    record = repository.get_by_idempotency_key(request.idempotency_key)

    assert record is not None
    assert record.request_hash == request_hash
    assert record.result == result


def test_result_ids_are_unique_across_repeated_invocations():
    request = _invocation()

    first = _result(request)
    second = _result(request)

    assert first.run_id != second.run_id
    assert first.result_id != second.result_id


def test_list_runs_returns_bounded_safe_summary_page(tmp_path):
    repository = SQLiteRunRepository(tmp_path / "runs.db")
    first_request = _invocation()
    first_result = _result(first_request)
    repository.save_completed_run(
        first_request,
        first_result,
        request_hash=canonical_request_hash(first_request),
        started_at=datetime.now(UTC),
    )

    second_request = first_request.model_copy(
        update={
            "request_id": "request-persistence-test-2",
            "idempotency_key": "idempotency-persistence-test-2",
        }
    )
    second_result = _result(second_request)
    repository.save_completed_run(
        second_request,
        second_result,
        request_hash=canonical_request_hash(second_request),
        started_at=datetime.now(UTC),
    )

    first_page = repository.list_runs(limit=1, offset=0)
    second_page = repository.list_runs(limit=1, offset=1)

    assert first_page.total == 2
    assert len(first_page.items) == 1
    assert len(second_page.items) == 1
    assert first_page.items[0].run_id == second_result.run_id
    assert second_page.items[0].run_id == first_result.run_id
    assert first_page.terminal_state_counts == {"translated": 2}
    summary = first_page.items[0].model_dump()
    assert summary["vulnerability_id"] == "CVE-EXAMPLE"
    assert summary["target_technology"] == "akamai-waf"
    assert summary["artifact_type"] == "akamai-waf-rule"
    assert "request_json" not in summary
    assert "content" not in summary
