"""Databricks SQL persistence for shared control-translation results."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from datetime import datetime, timezone
from hashlib import sha256
from threading import Lock
from typing import Any, Protocol

from control_translation.contracts import InvokeRequestEnvelope, ResultEnvelope, RunSummary
from control_translation.persistence.base import (
    IdempotencyRecord,
    PersistenceError,
    RunSummaryPage,
    canonical_request_hash,
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9_]+$")


class _Cursor(Protocol):
    def execute(self, operation: str, parameters: tuple[Any, ...] | None = None) -> Any: ...
    def fetchone(self) -> Any: ...
    def fetchall(self) -> list[Any]: ...
    def close(self) -> None: ...


class _Connection(Protocol):
    def cursor(self) -> _Cursor: ...
    def close(self) -> None: ...


ConnectionFactory = Callable[[], _Connection]


class DatabricksRunRepository:
    """Store completed runs in an existing Unity Catalog results table."""

    def __init__(
        self,
        *,
        server_hostname: str,
        http_path: str,
        auth_type: str = "oauth-m2m",
        token: str | None = None,
        client_id: str | None = None,
        client_secret: str | None = None,
        catalog: str,
        schema: str,
        table: str,
        connection_factory: ConnectionFactory | None = None,
    ) -> None:
        self._server_hostname = server_hostname.strip()
        self._http_path = http_path.strip()
        self._auth_type = auth_type.strip().lower()
        if self._auth_type not in {"oauth-m2m", "pat"}:
            raise ValueError("Invalid Databricks authentication type.")
        self._token = token
        self._client_id = client_id.strip() if client_id else None
        self._client_secret = client_secret
        self._table_name = ".".join(
            _quote_identifier(value, label)
            for value, label in (
                (catalog, "catalog"),
                (schema, "schema"),
                (table, "table"),
            )
        )
        self._connection_factory = connection_factory or self._default_connection
        self._initialization_lock = Lock()
        self._initialized = False

    def _default_connection(self) -> _Connection:
        """Create the configured SQL connection without imports during SQLite use."""
        try:
            from databricks import sql
        except ImportError as exc:  # pragma: no cover - depends on deployment image
            raise PersistenceError(
                "Databricks persistence dependencies are unavailable."
            ) from exc

        if self._auth_type == "pat":
            if not self._token:
                raise PersistenceError(
                    "Databricks PAT authentication configuration is incomplete."
                )
            return sql.connect(
                server_hostname=self._server_hostname,
                http_path=self._http_path,
                access_token=self._token,
            )

        try:
            from databricks.sdk.core import Config, oauth_service_principal
        except ImportError as exc:  # pragma: no cover - depends on deployment image
            raise PersistenceError(
                "Databricks OAuth dependencies are unavailable."
            ) from exc
        if not self._client_id or not self._client_secret:
            raise PersistenceError(
                "Databricks OAuth configuration is incomplete."
            )
        config = Config(
            host=f"https://{self._server_hostname}",
            client_id=self._client_id,
            client_secret=self._client_secret,
        )
        return sql.connect(
            server_hostname=self._server_hostname,
            http_path=self._http_path,
            credentials_provider=lambda: oauth_service_principal(config),
        )

    def initialize(self) -> None:
        """Verify that the configured principal can read the existing table."""
        if self._initialized:
            return
        with self._initialization_lock:
            if self._initialized:
                return
            try:
                self._execute(
                    f"SELECT result_id FROM {self._table_name} LIMIT 0"
                )
                self._initialized = True
            except PersistenceError:
                raise
            except Exception as exc:
                raise PersistenceError(
                    "Unable to initialize durable run storage."
                ) from exc

    def healthcheck(self) -> bool:
        try:
            self.initialize()
            row = self._execute("SELECT 1", fetch="one")
            return row is not None and row[0] == 1
        except Exception:
            return False

    def save_completed_run(
        self,
        request: InvokeRequestEnvelope,
        result: ResultEnvelope,
        *,
        request_hash: str,
        started_at: datetime,
    ) -> None:
        """Atomically insert one completed result; retrying its result ID is safe."""
        del request_hash  # Recomputed from request_json during idempotency lookup.
        self.initialize()
        structured_json = result.structured_result.model_dump_json()
        completion_json = result.model_dump_json()
        request_json = request.model_dump_json()
        result_bytes = structured_json.encode("utf-8")
        evidence_refs = sorted(
            {
                reference
                for binding in result.structured_result.evidence_bindings
                for reference in binding.evidence_refs
            }
            | set(result.provenance)
        )
        if request.upstream_result_refs is not None:
            upstream_result_refs = [
                reference.key
                for reference in (
                    request.upstream_result_refs.defense_generation,
                    request.upstream_result_refs.mitigation_check,
                    request.upstream_result_refs.bypass_validation,
                )
            ]
        elif request.input.proven_pattern is not None:
            upstream_result_refs = request.input.proven_pattern.proof_record_ids
        else:
            upstream_result_refs = []
        created_at = started_at.astimezone(timezone.utc)

        sql = f"""
            MERGE INTO {self._table_name} AS target
            USING (SELECT ? AS result_id) AS source
            ON target.result_id = source.result_id
            WHEN NOT MATCHED THEN INSERT (
                result_id, run_id, request_id, correlation_id, capability,
                contract_id, terminal_state, status, subject_record_revision_id,
                request_json, result_json, completion_json, result_sha256,
                result_size_bytes, evidence_refs, upstream_result_refs, created_at
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?,
                PARSE_JSON(?), PARSE_JSON(?), PARSE_JSON(?), ?, ?,
                PARSE_JSON(?), PARSE_JSON(?), ?
            )
        """
        parameters = (
            result.result_id,
            result.result_id,
            result.run_id,
            request.request_id,
            result.correlation_id,
            result.capability,
            result.contract_id,
            result.terminal_state.value,
            result.status,
            request.subject_record_revision_id,
            request_json,
            structured_json,
            completion_json,
            sha256(result_bytes).hexdigest(),
            len(result_bytes),
            _compact_json(evidence_refs),
            _compact_json(upstream_result_refs),
            created_at,
        )
        try:
            self._execute(sql, parameters)
        except PersistenceError:
            raise
        except Exception as exc:
            raise PersistenceError(
                "Unable to persist the completed capability run."
            ) from exc

    def get_run(self, run_id: str) -> ResultEnvelope | None:
        return self._get_result_envelope("run_id = ?", run_id)

    def get_result(self, result_id: str) -> ResultEnvelope | None:
        return self._get_result_envelope("result_id = ?", result_id)

    def _get_result_envelope(
        self, where_clause: str, value: str
    ) -> ResultEnvelope | None:
        self.initialize()
        try:
            row = self._execute(
                f"""
                SELECT TO_JSON(completion_json)
                FROM {self._table_name}
                WHERE {where_clause}
                LIMIT 1
                """,
                (value,),
                fetch="one",
            )
        except PersistenceError:
            raise
        except Exception as exc:
            raise PersistenceError("Unable to read durable run storage.") from exc
        if row is None:
            return None
        return _validate_result(row[0], "Stored result failed contract validation.")

    def get_by_idempotency_key(self, key: str) -> IdempotencyRecord | None:
        self.initialize()
        try:
            row = self._execute(
                f"""
                SELECT TO_JSON(request_json), TO_JSON(completion_json)
                FROM {self._table_name}
                WHERE request_json:idempotency_key::STRING = ?
                ORDER BY created_at ASC
                LIMIT 1
                """,
                (key,),
                fetch="one",
            )
        except PersistenceError:
            raise
        except Exception as exc:
            raise PersistenceError("Unable to read idempotency state.") from exc
        if row is None:
            return None
        try:
            request = InvokeRequestEnvelope.model_validate_json(row[0])
        except ValueError as exc:
            raise PersistenceError(
                "Stored idempotency request failed validation."
            ) from exc
        result = _validate_result(
            row[1], "Stored idempotency result failed validation."
        )
        return IdempotencyRecord(
            request_hash=canonical_request_hash(request),
            result=result,
        )

    def list_runs(self, *, limit: int, offset: int) -> RunSummaryPage:
        """Return a bounded metadata projection without loading artifact content."""
        self.initialize()
        try:
            rows = self._execute(
                f"""
                SELECT
                    run_id,
                    result_id,
                    correlation_id,
                    status,
                    terminal_state,
                    result_json:outcome_reason.code::STRING,
                    result_json:subject.vulnerability_id::STRING,
                    result_json:input_bindings.target_technology::STRING,
                    result_json:primary_candidate.candidate_artifact.artifact_type::STRING,
                    created_at,
                    TRY_CAST(result_json:produced_at::STRING AS TIMESTAMP)
                FROM {self._table_name}
                ORDER BY created_at DESC, run_id DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
                fetch="all",
            )
            total_row = self._execute(
                f"SELECT COUNT(*) FROM {self._table_name}", fetch="one"
            )
            count_rows = self._execute(
                f"""
                SELECT terminal_state, COUNT(*)
                FROM {self._table_name}
                GROUP BY terminal_state
                """,
                fetch="all",
            )
        except PersistenceError:
            raise
        except Exception as exc:
            raise PersistenceError("Unable to list durable run storage.") from exc

        try:
            items = tuple(
                RunSummary(
                    run_id=row[0],
                    result_id=row[1],
                    correlation_id=row[2],
                    status=row[3],
                    terminal_state=row[4],
                    outcome_reason_code=row[5],
                    vulnerability_id=row[6],
                    target_technology=row[7],
                    artifact_type=row[8],
                    started_at=row[9],
                    completed_at=row[10] or row[9],
                    result_href=f"/v1/results/{row[1]}",
                )
                for row in rows
            )
        except (TypeError, ValueError) as exc:
            raise PersistenceError("Stored run summary failed validation.") from exc
        return RunSummaryPage(
            items=items,
            total=int(total_row[0]) if total_row else 0,
            terminal_state_counts={row[0]: int(row[1]) for row in count_rows},
        )

    def _execute(
        self,
        operation: str,
        parameters: tuple[Any, ...] | None = None,
        *,
        fetch: str | None = None,
    ) -> Any:
        connection: _Connection | None = None
        cursor: _Cursor | None = None
        try:
            connection = self._connection_factory()
            cursor = connection.cursor()
            cursor.execute(operation, parameters)
            if fetch == "one":
                return cursor.fetchone()
            if fetch == "all":
                return cursor.fetchall()
            return None
        finally:
            if cursor is not None:
                try:
                    cursor.close()
                except Exception:
                    pass
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    pass


def _quote_identifier(value: str, label: str) -> str:
    normalized = value.strip()
    if not normalized or _IDENTIFIER.fullmatch(normalized) is None:
        raise ValueError(f"Invalid Databricks {label} identifier.")
    return f"`{normalized}`"


def _compact_json(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)


def _validate_result(value: str, message: str) -> ResultEnvelope:
    try:
        return ResultEnvelope.model_validate_json(value)
    except (TypeError, ValueError) as exc:
        raise PersistenceError(message) from exc
