"""Databricks SQL persistence for shared control-translation results."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import Lock
from time import perf_counter
from typing import Any, Protocol

from control_translation.contracts import (
    CapabilityRunStatus,
    InvokeRequestEnvelope,
    ResultEnvelope,
    RunFailure,
    RunProgress,
    RunSummary,
)
from control_translation.callbacks import CallbackMetadata
from control_translation.persistence.base import (
    CreatedLifecycleRun,
    IdempotencyConflictError,
    IdempotencyRecord,
    LifecycleRun,
    PersistenceError,
    RunSummaryPage,
    canonical_result_bytes,
    canonical_request_hash,
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9_]+$")
logger = logging.getLogger(__name__)


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
        runs_table: str = "control_translation_runs",
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
        self._runs_table_name = ".".join(
            _quote_identifier(value, label)
            for value, label in (
                (catalog, "catalog"),
                (schema, "schema"),
                (runs_table, "runs table"),
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
            logger.exception(
                "Databricks storage healthcheck failed table=%s",
                self._table_name,
            )
            return False

    def save_completed_run(
        self,
        request: InvokeRequestEnvelope,
        result: ResultEnvelope,
        *,
        request_hash: str,
        started_at: datetime,
        canonical_result: dict | None = None,
    ) -> None:
        """Atomically insert one completed result; retrying its result ID is safe."""
        del request_hash  # Recomputed from request_json during idempotency lookup.
        self.initialize()
        structured_json = (
            canonical_result_bytes(canonical_result).decode("utf-8")
            if canonical_result is not None
            else result.structured_result.model_dump_json()
        )
        if canonical_result is not None:
            contract_id, status, terminal_state = _canonical_row_state(
                canonical_result
            )
        else:
            contract_id = result.contract_id
            status = result.status
            terminal_state = result.terminal_state.value
        completion_json = result.model_dump_json()
        request_json = request.model_dump_json()
        result_bytes = structured_json.encode("utf-8")
        result_digest = sha256(result_bytes).hexdigest()
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
        created_at = started_at.astimezone(UTC)

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
            contract_id,
            terminal_state,
            status,
            request.subject_record_revision_id,
            request_json,
            structured_json,
            completion_json,
            result_digest,
            len(result_bytes),
            _compact_json(evidence_refs),
            _compact_json(upstream_result_refs),
            created_at,
        )
        try:
            self._execute(sql, parameters)
            persisted = self._execute(
                f"""
                SELECT run_id, contract_id, status, terminal_state,
                    result_sha256, result_size_bytes, TO_JSON(result_json),
                    TO_JSON(completion_json)
                FROM {self._table_name}
                WHERE result_id = ?
                LIMIT 1
                """,
                (result.result_id,),
                fetch="one",
            )
            if persisted is None or (
                persisted[0] != result.run_id
                or persisted[1] != contract_id
                or persisted[2] != status
                or persisted[3] != terminal_state
                or persisted[4] != result_digest
                or int(persisted[5]) != len(result_bytes)
                or _parse_json_object(
                    persisted[6],
                    "Stored Databricks canonical result failed validation.",
                )
                != _parse_json_object(
                    structured_json,
                    "Canonical result failed validation.",
                )
                or _validate_result(
                    persisted[7],
                    "Stored Databricks completion failed contract validation.",
                )
                != result
            ):
                raise PersistenceError(
                    "Immutable Databricks result identity conflicts with stored content."
                )
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
                    completion_json:structured_result.outcome_reason.code::STRING,
                    completion_json:structured_result.subject.vulnerability_id::STRING,
                    completion_json:structured_result.input_bindings.target_technology::STRING,
                    completion_json:structured_result.primary_candidate.candidate_artifact.artifact_type::STRING,
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

    def create_lifecycle_run(
        self,
        request: InvokeRequestEnvelope,
        *,
        idempotency_key: str,
        request_digest: str,
        run_id: str | None = None,
        callback: CallbackMetadata | None = None,
    ) -> CreatedLifecycleRun:
        del callback
        from uuid import uuid4

        self.initialize()
        effective_run_id = run_id or str(uuid4())
        now = datetime.now(UTC)
        try:
            self._execute(
                f"""
                MERGE INTO {self._runs_table_name} AS target
                USING (SELECT ? AS idempotency_key) AS source
                ON target.idempotency_key = source.idempotency_key
                WHEN NOT MATCHED THEN INSERT (
                    run_id, request_id, correlation_id, idempotency_key,
                    request_digest, request_json, status, progress_phase,
                    progress_message, cancel_requested, attempt_number,
                    created_at, accepted_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, PARSE_JSON(?), 'queued', 'queued', ?,
                    false, 0, ?, ?, ?)
                """,
                (
                    idempotency_key,
                    effective_run_id,
                    request.request_id,
                    request.correlation_id,
                    idempotency_key,
                    request_digest,
                    request.model_dump_json(by_alias=True),
                    "Translation is queued.",
                    now,
                    now,
                    now,
                ),
            )
            row = self._select_lifecycle("idempotency_key = ?", idempotency_key)
        except PersistenceError:
            raise
        except Exception as exc:
            raise PersistenceError("Unable to create durable lifecycle run.") from exc
        if row is None:
            raise PersistenceError("Created lifecycle run could not be read.")
        if row.request_digest != request_digest:
            raise IdempotencyConflictError(
                "Idempotency key is already bound to different input."
            )
        return CreatedLifecycleRun(
            run=row,
            created=row.status.run_id == effective_run_id,
        )

    def get_lifecycle_run(self, run_id: str) -> LifecycleRun | None:
        self.initialize()
        return self._select_lifecycle("run_id = ?", run_id)

    def get_lifecycle_result(self, run_id: str) -> dict | None:
        self.initialize()
        try:
            row = self._execute(
                f"SELECT TO_JSON(result_json) FROM {self._runs_table_name} WHERE run_id = ? LIMIT 1",
                (run_id,),
                fetch="one",
            )
        except Exception as exc:
            raise PersistenceError("Unable to read durable lifecycle result.") from exc
        if row is None or row[0] is None:
            return None
        try:
            return json.loads(row[0])
        except (TypeError, ValueError) as exc:
            raise PersistenceError("Stored lifecycle result is invalid.") from exc

    def claim_lifecycle_run(
        self, *, worker_id: str, lease_seconds: int, max_attempts: int
    ) -> LifecycleRun | None:
        self.initialize()
        now = datetime.now(UTC)
        lease = now + timedelta(seconds=lease_seconds)
        try:
            self._execute(
                f"""
                UPDATE {self._runs_table_name}
                SET status = 'canceled', terminal_state = 'canceled',
                    progress_phase = 'canceled', progress_message = ?,
                    completed_at = ?, updated_at = ?, worker_id = NULL,
                    lease_expires_at = NULL
                WHERE status = 'running' AND cancel_requested = true
                  AND lease_expires_at < ?
                """,
                ("Cancellation completed after worker lease expiry.", now, now, now),
            )
            self._execute(
                f"""
                UPDATE {self._runs_table_name}
                SET status = 'failed', terminal_state = 'malfunction',
                    failure_json = PARSE_JSON(?), progress_phase = 'failed',
                    progress_message = ?, completed_at = ?, updated_at = ?,
                    worker_id = NULL, lease_expires_at = NULL
                WHERE status = 'running' AND cancel_requested = false
                  AND lease_expires_at < ? AND attempt_number >= ?
                """,
                (
                    RunFailure(
                        code="worker_attempts_exhausted",
                        detail="Worker lease expired and the bounded attempt limit was reached.",
                        retryable=False,
                    ).model_dump_json(),
                    "Worker attempts exhausted.",
                    now,
                    now,
                    now,
                    max_attempts,
                ),
            )
            self._execute(
                f"""
                UPDATE {self._runs_table_name}
                SET status = 'running', worker_id = ?, lease_expires_at = ?,
                    last_heartbeat_at = ?, attempt_number = attempt_number + 1,
                    started_at = COALESCE(started_at, ?), updated_at = ?,
                    progress_phase = 'translating', progress_message = ?
                WHERE run_id = (
                    SELECT run_id FROM {self._runs_table_name}
                    WHERE cancel_requested = false AND attempt_number < ?
                      AND (status = 'queued' OR (status = 'running' AND lease_expires_at < ?))
                    ORDER BY created_at, run_id LIMIT 1
                )
                """,
                (
                    worker_id,
                    lease,
                    now,
                    now,
                    now,
                    "Translation is running.",
                    max_attempts,
                    now,
                ),
            )
            row = self._select_lifecycle(
                "worker_id = ? AND status = 'running'", worker_id
            )
        except Exception as exc:
            raise PersistenceError("Unable to claim durable lifecycle run.") from exc
        return row

    def heartbeat_lifecycle_run(
        self,
        run_id: str,
        *,
        worker_id: str,
        attempt_number: int,
        lease_seconds: int,
    ) -> bool:
        now = datetime.now(UTC)
        self._execute(
            f"""
            UPDATE {self._runs_table_name}
            SET lease_expires_at = ?, last_heartbeat_at = ?, updated_at = ?
            WHERE run_id = ? AND status = 'running' AND worker_id = ?
                            AND attempt_number = ?
            """,
                        (
                                now + timedelta(seconds=lease_seconds),
                                now,
                                now,
                                run_id,
                                worker_id,
                                attempt_number,
                        ),
        )
        row = self._select_lifecycle("run_id = ?", run_id)
        return row is not None and row.worker_id == worker_id and row.status.status == "running"

    def complete_lifecycle_run(
        self,
        run_id: str,
        *,
        worker_id: str,
        attempt_number: int,
        result: dict,
        completion: dict,
        result_id: str,
        terminal_state: str,
    ) -> bool:
        now = datetime.now(UTC)
        self._execute(
            f"""
            UPDATE {self._runs_table_name}
            SET status = CASE WHEN cancel_requested THEN 'canceled' ELSE 'completed' END,
                terminal_state = CASE WHEN cancel_requested THEN 'canceled' ELSE ? END,
                result_id = CASE WHEN cancel_requested THEN NULL ELSE ? END,
                result_json = CASE WHEN cancel_requested THEN NULL ELSE PARSE_JSON(?) END,
                completion_json = CASE WHEN cancel_requested THEN NULL ELSE PARSE_JSON(?) END,
                progress_phase = CASE WHEN cancel_requested THEN 'canceled' ELSE 'completed' END,
                progress_percent = CASE WHEN cancel_requested THEN NULL ELSE 100 END,
                progress_message = CASE WHEN cancel_requested THEN ? ELSE ? END,
                completed_at = ?, updated_at = ?, worker_id = NULL, lease_expires_at = NULL
                        WHERE run_id = ? AND status = 'running' AND worker_id = ?
                            AND attempt_number = ? AND result_json IS NULL
            """,
            (
                terminal_state,
                result_id,
                _compact_json(result),
                _compact_json(completion),
                "Cancellation completed.",
                "Translation completed.",
                now,
                now,
                run_id,
                worker_id,
                attempt_number,
            ),
        )
        row = self._select_lifecycle("run_id = ?", run_id)
        return row is not None and row.status.status == "completed"

    def fail_lifecycle_run(
        self,
        run_id: str,
        *,
        worker_id: str,
        attempt_number: int,
        failure: RunFailure,
        result: dict | None = None,
    ) -> bool:
        now = datetime.now(UTC)
        self._execute(
            f"""
            UPDATE {self._runs_table_name}
            SET status = CASE WHEN cancel_requested THEN 'canceled' ELSE 'failed' END,
                terminal_state = CASE WHEN cancel_requested THEN 'canceled' ELSE 'malfunction' END,
                failure_json = CASE WHEN cancel_requested THEN NULL ELSE PARSE_JSON(?) END,
                result_json = CASE WHEN cancel_requested OR ? IS NULL THEN NULL ELSE PARSE_JSON(?) END,
                progress_phase = CASE WHEN cancel_requested THEN 'canceled' ELSE 'failed' END,
                progress_message = CASE WHEN cancel_requested THEN ? ELSE ? END,
                completed_at = ?, updated_at = ?, worker_id = NULL, lease_expires_at = NULL
                        WHERE run_id = ? AND status = 'running' AND worker_id = ?
                            AND attempt_number = ?
            """,
            (
                failure.model_dump_json(),
                _compact_json(result) if result is not None else None,
                _compact_json(result) if result is not None else None,
                failure.detail,
                now,
                now,
                run_id,
                worker_id,
                attempt_number,
            ),
        )
        row = self._select_lifecycle("run_id = ?", run_id)
        return row is not None and row.status.status in {"failed", "canceled"}

    def cancel_lifecycle_run(self, run_id: str) -> LifecycleRun | None:
        now = datetime.now(UTC)
        self._execute(
            f"""
            UPDATE {self._runs_table_name}
            SET cancel_requested = true,
                status = 'canceled', terminal_state = 'canceled',
                progress_phase = 'canceled',
                progress_message = CASE WHEN status = 'queued' THEN ? ELSE ? END,
                completed_at = ?, worker_id = NULL, lease_expires_at = NULL,
                updated_at = CASE WHEN status IN ('queued', 'running') THEN ? ELSE updated_at END
            WHERE run_id = ? AND status IN ('queued', 'running')
            """,
            (
                "Run canceled before execution.",
                "Cancellation completed.",
                now,
                now,
                run_id,
            ),
        )
        return self._select_lifecycle("run_id = ?", run_id)

    def _select_lifecycle(self, where_clause: str, value: str) -> LifecycleRun | None:
        try:
            row = self._execute(
                f"""
                SELECT run_id, request_id, correlation_id, request_digest,
                    TO_JSON(request_json), status, terminal_state, result_id,
                    TO_JSON(completion_json), TO_JSON(failure_json), progress_phase,
                    progress_percent, progress_message, cancel_requested, worker_id,
                    attempt_number, created_at, started_at, updated_at, completed_at
                FROM {self._runs_table_name}
                WHERE {where_clause}
                ORDER BY created_at LIMIT 1
                """,
                (value,),
                fetch="one",
            )
        except Exception as exc:
            raise PersistenceError("Unable to read durable lifecycle run.") from exc
        if row is None:
            return None
        try:
            request = InvokeRequestEnvelope.model_validate_json(row[4])
            failure = RunFailure.model_validate_json(row[9]) if row[9] else None
            status = CapabilityRunStatus(
                request_id=row[1],
                correlation_id=row[2],
                run_id=row[0],
                status=row[5],
                terminal_state=row[6],
                result_id=row[7],
                created_at=row[16],
                started_at=row[17],
                updated_at=row[18],
                completed_at=row[19],
                progress=RunProgress(
                    phase=row[10], percent=row[11], message=row[12]
                ),
                failure=failure,
                completion=json.loads(row[8]) if row[8] else None,
            )
        except (TypeError, ValueError) as exc:
            raise PersistenceError("Stored lifecycle run failed validation.") from exc
        return LifecycleRun(
            request=request,
            status=status,
            request_digest=row[3],
            cancel_requested=bool(row[13]),
            worker_id=row[14],
            attempt_number=int(row[15]),
            publication_state="none",
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
        statement_type = operation.lstrip().split(maxsplit=1)[0].upper()
        parameter_count = len(parameters) if parameters is not None else 0
        started = perf_counter()
        logger.info(
            "Databricks SQL started statement_type=%s table=%s fetch=%s "
            "parameter_count=%s",
            statement_type,
            self._table_name,
            fetch or "none",
            parameter_count,
        )
        try:
            connection = self._connection_factory()
            cursor = connection.cursor()
            cursor.execute(operation, parameters)
            if fetch == "one":
                result = cursor.fetchone()
            elif fetch == "all":
                result = cursor.fetchall()
            else:
                result = None
            logger.info(
                "Databricks SQL completed statement_type=%s table=%s fetch=%s "
                "duration_ms=%.2f",
                statement_type,
                self._table_name,
                fetch or "none",
                (perf_counter() - started) * 1000,
            )
            return result
        except Exception as exc:
            error_type = type(exc).__name__
            error_code = getattr(exc, "error_code", None) or "-"
            sql_state = getattr(exc, "sql_state", None) or "-"
            logger.exception(
                "Databricks SQL failed statement_type=%s table=%s fetch=%s "
                "parameter_count=%s duration_ms=%.2f error_type=%s "
                "error_code=%s sql_state=%s",
                statement_type,
                self._table_name,
                fetch or "none",
                parameter_count,
                (perf_counter() - started) * 1000,
                error_type,
                error_code,
                sql_state,
            )
            raise
        finally:
            if cursor is not None:
                try:
                    cursor.close()
                except Exception:
                    logger.warning(
                        "Databricks cursor close failed table=%s",
                        self._table_name,
                        exc_info=True,
                    )
            if connection is not None:
                try:
                    connection.close()
                except Exception:
                    logger.warning(
                        "Databricks connection close failed table=%s",
                        self._table_name,
                        exc_info=True,
                    )


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


def _canonical_row_state(result: dict) -> tuple[str, str, str]:
    """Validate scalar columns owned by the canonical async result contract."""
    contract_id = result.get("contract_id")
    status = result.get("status")
    terminal_state = result.get("terminal_state")
    if contract_id != "control-translation-result@1.0":
        raise PersistenceError("Canonical result contract_id is invalid.")
    if status != "completed":
        raise PersistenceError("Canonical result status must be completed.")
    if terminal_state not in {"translated", "not-translatable", "malfunction"}:
        raise PersistenceError("Canonical result terminal_state is invalid.")
    return contract_id, status, terminal_state


def _parse_json_object(value: str, message: str) -> dict:
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError) as exc:
        raise PersistenceError(message) from exc
    if not isinstance(parsed, dict):
        raise PersistenceError(message)
    return parsed
