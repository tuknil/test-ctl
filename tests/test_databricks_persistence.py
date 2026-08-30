from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
from types import ModuleType
from typing import Any
import sys

import pytest

from control_translation import capability
from control_translation.config import Settings
from control_translation.contracts import (
    ControlTranslationRequest,
    InvokeRequestEnvelope,
    TargetContext,
)
from control_translation.persistence import (
    DatabricksRunRepository,
    PersistenceError,
    SQLiteRunRepository,
    canonical_request_hash,
    create_run_repository,
)
from control_translation.providers.fixtures import get_fixture_pattern


class FakeCursor:
    def __init__(self, response: Any, executions: list[tuple[str, Any]]) -> None:
        self.response = response
        self.executions = executions
        self.closed = False

    def execute(self, operation: str, parameters=None):
        self.executions.append((operation, parameters))

    def fetchone(self):
        return self.response

    def fetchall(self):
        return self.response

    def close(self):
        self.closed = True


class FakeConnection:
    def __init__(self, response: Any, executions: list[tuple[str, Any]]) -> None:
        self.cursor_instance = FakeCursor(response, executions)
        self.closed = False

    def cursor(self):
        return self.cursor_instance

    def close(self):
        self.closed = True


class ConnectionQueue:
    def __init__(self, *responses: Any) -> None:
        self.responses = list(responses)
        self.executions: list[tuple[str, Any]] = []
        self.connections: list[FakeConnection] = []

    def __call__(self):
        response = self.responses.pop(0) if self.responses else None
        connection = FakeConnection(response, self.executions)
        self.connections.append(connection)
        return connection


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
        request_id="request-databricks-test",
        correlation_id="correlation-databricks-test",
        idempotency_key="idempotency-databricks-test",
        subject_record_revision_id="subject-revision:42",
    )


def _result(request: InvokeRequestEnvelope):
    return capability.invoke(
        request.input,
        settings=Settings(run_mode="fixture", model_provider="none"),
        correlation_id=request.correlation_id,
    )


def _repository(queue: ConnectionQueue) -> DatabricksRunRepository:
    return DatabricksRunRepository(
        server_hostname="adb.example.azuredatabricks.net",
        http_path="/sql/1.0/warehouses/example",
        client_id="client-id",
        client_secret="not-a-real-secret",
        catalog="36889_janus_dev",
        schema="control_translation",
        table="control_translation_results",
        connection_factory=queue,
    )


def test_save_maps_contract_to_existing_databricks_table():
    queue = ConnectionQueue(None, None)
    repository = _repository(queue)
    request = _invocation()
    result = _result(request)
    started_at = datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc)

    repository.save_completed_run(
        request,
        result,
        request_hash=canonical_request_hash(request),
        started_at=started_at,
    )

    initialization_sql, _ = queue.executions[0]
    merge_sql, parameters = queue.executions[1]
    assert "`36889_janus_dev`.`control_translation`.`control_translation_results`" in initialization_sql
    assert "MERGE INTO" in merge_sql
    assert "PARSE_JSON(?)" in merge_sql
    assert parameters[0] == result.result_id
    assert parameters[2] == result.run_id
    assert parameters[9] == "subject-revision:42"
    assert parameters[10] == request.model_dump_json()
    assert parameters[11] == result.structured_result.model_dump_json()
    assert parameters[12] == result.model_dump_json()
    result_bytes = parameters[11].encode("utf-8")
    assert parameters[13] == sha256(result_bytes).hexdigest()
    assert parameters[14] == len(result_bytes)
    assert parameters[17] == started_at
    assert all(connection.closed for connection in queue.connections)
    assert all(connection.cursor_instance.closed for connection in queue.connections)


def test_result_and_idempotency_records_are_revalidated():
    request = _invocation()
    result = _result(request)
    queue = ConnectionQueue(
        None,
        (result.model_dump_json(),),
        (request.model_dump_json(), result.model_dump_json()),
    )
    repository = _repository(queue)

    assert repository.get_result(result.result_id) == result
    record = repository.get_by_idempotency_key(request.idempotency_key or "")

    assert record is not None
    assert record.result == result
    assert record.request_hash == canonical_request_hash(request)
    assert "request_json:idempotency_key::STRING = ?" in queue.executions[2][0]
    assert queue.executions[2][1] == (request.idempotency_key,)


def test_list_runs_returns_metadata_projection_only():
    request = _invocation()
    result = _result(request)
    produced_at = result.structured_result.produced_at
    queue = ConnectionQueue(
        None,
        [
            (
                result.run_id,
                result.result_id,
                result.correlation_id,
                result.status,
                result.terminal_state.value,
                result.structured_result.outcome_reason.code.value,
                request.input.proven_pattern.vulnerability_id,
                request.input.target_context.target_technology,
                "akamai-waf-rule",
                produced_at,
                produced_at,
            )
        ],
        (1,),
        [(result.terminal_state.value, 1)],
    )
    repository = _repository(queue)

    page = repository.list_runs(limit=25, offset=0)

    assert page.total == 1
    assert page.terminal_state_counts == {"translated": 1}
    assert page.items[0].run_id == result.run_id
    assert page.items[0].artifact_type == "akamai-waf-rule"
    listing_sql = queue.executions[1][0]
    assert "completion_json" not in listing_sql
    assert "candidate_artifact.artifact_type" in listing_sql


def test_identifiers_are_strictly_validated():
    with pytest.raises(ValueError, match="Invalid Databricks table identifier"):
        DatabricksRunRepository(
            server_hostname="adb.example.azuredatabricks.net",
            http_path="/sql/example",
            client_id="client-id",
            client_secret="secret",
            catalog="catalog",
            schema="schema",
            table="results; DROP TABLE results",
            connection_factory=ConnectionQueue(),
        )


def test_invalid_stored_completion_is_redacted_as_persistence_error():
    repository = _repository(ConnectionQueue(None, ("not-json",)))

    with pytest.raises(PersistenceError, match="contract validation"):
        repository.get_result("result-id")


def test_repository_factory_preserves_sqlite_default(tmp_path):
    repository = create_run_repository(Settings(database_path=str(tmp_path / "runs.db")))
    assert isinstance(repository, SQLiteRunRepository)


def test_repository_factory_requires_databricks_oauth_settings():
    settings = Settings(persistence_backend="databricks")

    assert settings.ready is False
    assert any("DATABRICKS_HTTP_PATH" in error for error in settings.configuration_errors)
    with pytest.raises(PersistenceError, match="configuration is incomplete"):
        create_run_repository(settings)


def test_repository_factory_accepts_pat_settings():
    settings = Settings(
        persistence_backend="databricks",
        databricks_server_hostname="adb.example.azuredatabricks.net",
        databricks_http_path="/sql/1.0/warehouses/example",
        databricks_auth_type="pat",
        databricks_token="test-token",
    )

    repository = create_run_repository(settings)

    assert settings.ready is True
    assert isinstance(repository, DatabricksRunRepository)


def test_pat_connection_uses_access_token_without_oauth_fields(monkeypatch):
    captured: dict[str, Any] = {}
    expected_connection = FakeConnection(None, [])

    class FakeSql:
        @staticmethod
        def connect(**kwargs):
            captured.update(kwargs)
            return expected_connection

    databricks_module = ModuleType("databricks")
    databricks_module.sql = FakeSql()
    monkeypatch.setitem(sys.modules, "databricks", databricks_module)
    repository = DatabricksRunRepository(
        server_hostname="adb.example.azuredatabricks.net",
        http_path="/sql/1.0/warehouses/example",
        auth_type="pat",
        token="test-token",
        catalog="catalog",
        schema="schema",
        table="results",
    )

    connection = repository._default_connection()

    assert connection is expected_connection
    assert captured == {
        "server_hostname": "adb.example.azuredatabricks.net",
        "http_path": "/sql/1.0/warehouses/example",
        "access_token": "test-token",
    }


def test_invalid_databricks_auth_type_is_not_ready():
    settings = Settings(
        persistence_backend="databricks",
        databricks_auth_type="password",
    )

    assert settings.ready is False
    assert any("DATABRICKS_AUTH_TYPE" in error for error in settings.configuration_errors)


def test_subject_revision_participates_in_idempotency_hash():
    request = _invocation()
    changed = request.model_copy(update={"subject_record_revision_id": "subject-revision:43"})

    assert canonical_request_hash(request) != canonical_request_hash(changed)
