"""Secure, transaction-oriented SQLite persistence for capability runs."""

from __future__ import annotations

import json
import logging
import os
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Lock

from control_translation.callbacks import (
    CallbackDelivery,
    CallbackMetadata,
)
from control_translation.contracts import (
    CapabilityRunStatus,
    InvokeRequestEnvelope,
    ResultEnvelope,
    RunFailure,
    RunProgress,
    RunSummary,
)
from control_translation.persistence.base import (
    CreatedLifecycleRun,
    IdempotencyConflictError,
    IdempotencyRecord,
    LifecycleRun,
    PreparedPublication,
    PersistenceError,
    RunSummaryPage,
)
from control_translation.persistence.migrations import MIGRATIONS

logger = logging.getLogger(__name__)


class SQLiteRunRepository:
    """Durable single-instance storage backed by a local SQLite file."""

    def __init__(self, database_path: str | Path) -> None:
        self._path = Path(database_path).expanduser()
        self._initialization_lock = Lock()
        self._initialized = False

    @property
    def database_path(self) -> Path:
        return self._path

    def _connect(self) -> sqlite3.Connection:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(str(self._path), timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        # The lifecycle database lives on a mounted single-replica volume.
        # Rollback journaling avoids WAL sidecar semantics on network storage.
        connection.execute("PRAGMA journal_mode = DELETE")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def initialize(self) -> None:
        if self._initialized:
            return
        with self._initialization_lock:
            if self._initialized:
                return
            try:
                with self._connect() as connection:
                    connection.execute(
                        """
                        CREATE TABLE IF NOT EXISTS schema_migrations (
                            version INTEGER PRIMARY KEY,
                            name TEXT NOT NULL,
                            applied_at TEXT NOT NULL
                        )
                        """
                    )

                for version, name, sql in MIGRATIONS:
                    with self._connect() as connection:
                        applied = connection.execute(
                            "SELECT 1 FROM schema_migrations WHERE version = ?",
                            (version,),
                        ).fetchone()
                        if applied is not None:
                            continue
                        safe_name = name.replace("'", "''")
                        applied_at = _utc_now().replace("'", "''")
                        connection.executescript(
                            "BEGIN IMMEDIATE;\n"
                            + sql
                            + "\nINSERT INTO schema_migrations(version, name, applied_at) "
                            + f"VALUES ({version}, '{safe_name}', '{applied_at}');\n"
                            + "COMMIT;"
                        )

                self._restrict_file_permissions()
                self._initialized = True
            except (OSError, sqlite3.Error) as exc:
                raise PersistenceError("Unable to initialize durable run storage.") from exc

    def _restrict_file_permissions(self) -> None:
        """Apply owner-only permissions where the host supports POSIX modes."""
        try:
            os.chmod(self._path, 0o600)
        except OSError:
            # Windows and managed volumes enforce access through their own ACLs.
            pass

    def healthcheck(self) -> bool:
        try:
            self.initialize()
            with self._connect() as connection:
                return connection.execute("SELECT 1").fetchone()[0] == 1
        except (PersistenceError, OSError, sqlite3.Error):
            logger.exception(
                "SQLite storage healthcheck failed database=%s",
                self._path,
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
        del canonical_result  # Lifecycle result JSON is stored by the fenced terminal write.
        self.initialize()
        already_persisted = self.get_run(result.run_id)
        if already_persisted is not None:
            if already_persisted == result:
                return
            raise PersistenceError(
                "Immutable SQLite result identity conflicts with stored content."
            )
        structured = result.structured_result
        completed_at = structured.produced_at.astimezone(UTC).isoformat()
        now = _utc_now()
        request_json = request.model_dump_json()
        result_json = result.model_dump_json()

        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    INSERT INTO capability_runs (
                        run_id, capability, contract_id, request_id,
                        correlation_id, idempotency_key, request_hash, result_id,
                        status, terminal_state, outcome_reason_code, started_at,
                        completed_at, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result.run_id,
                        result.capability,
                        structured.contract_id,
                        request.request_id,
                        result.correlation_id,
                        request.idempotency_key,
                        request_hash,
                        result.result_id,
                        result.status,
                        result.terminal_state.value,
                        structured.outcome_reason.code.value,
                        started_at.astimezone(UTC).isoformat(),
                        completed_at,
                        now,
                        now,
                    ),
                )
                connection.execute(
                    """
                    INSERT INTO invocation_payloads (
                        run_id, request_json, result_json, prose_summary,
                        inference_json, warnings_json, trace_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        result.run_id,
                        request_json,
                        result_json,
                        result.prose,
                        json.dumps(result.inference, separators=(",", ":")),
                        json.dumps(result.warnings, separators=(",", ":")),
                        json.dumps(result.trace, separators=(",", ":")),
                    ),
                )
                self._insert_artifact(connection, result, now)
                self._insert_evidence(connection, result, now)
                connection.commit()
        except (OSError, sqlite3.Error) as exc:
            raise PersistenceError("Unable to persist the completed capability run.") from exc

    def _insert_artifact(
        self,
        connection: sqlite3.Connection,
        result: ResultEnvelope,
        created_at: str,
    ) -> None:
        candidate = result.structured_result.primary_candidate
        if candidate is None:
            return
        artifact = candidate.candidate_artifact
        connection.execute(
            """
            INSERT INTO result_artifacts (
                run_id, artifact_id, result_id, artifact_type, content,
                content_hash, emitted_as, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                result.run_id,
                candidate.candidate_id,
                result.result_id,
                artifact.artifact_type,
                artifact.content_ref,
                artifact.content_hash,
                artifact.emitted_as,
                created_at,
            ),
        )

    def _insert_evidence(
        self,
        connection: sqlite3.Connection,
        result: ResultEnvelope,
        created_at: str,
    ) -> None:
        references: set[tuple[str, str]] = set()
        for binding in result.structured_result.evidence_bindings:
            references.update((binding.claim, ref) for ref in binding.evidence_refs)
        references.update(("provenance", ref) for ref in result.provenance)

        connection.executemany(
            """
            INSERT INTO evidence_references (
                run_id, result_id, claim, evidence_ref, created_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            [
                (result.run_id, result.result_id, claim, evidence_ref, created_at)
                for claim, evidence_ref in sorted(references)
            ],
        )

    def get_run(self, run_id: str) -> ResultEnvelope | None:
        return self._get_result_envelope("runs.run_id = ?", run_id)

    def get_result(self, result_id: str) -> ResultEnvelope | None:
        return self._get_result_envelope("runs.result_id = ?", result_id)

    def list_runs(self, *, limit: int, offset: int) -> RunSummaryPage:
        """Return newest-first metadata only; never load stored full payloads."""
        self.initialize()
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    """
                    SELECT
                        runs.run_id,
                        runs.result_id,
                        runs.correlation_id,
                        runs.status,
                        runs.terminal_state,
                        runs.outcome_reason_code,
                        runs.started_at,
                        runs.completed_at,
                        json_extract(
                            payloads.result_json,
                            '$.structured_result.subject.vulnerability_id'
                        ) AS vulnerability_id,
                        json_extract(
                            payloads.result_json,
                            '$.structured_result.input_bindings.target_technology'
                        ) AS target_technology,
                        (
                            SELECT artifact_type
                            FROM result_artifacts AS artifacts
                            WHERE artifacts.run_id = runs.run_id
                            ORDER BY artifacts.artifact_id
                            LIMIT 1
                        ) AS artifact_type
                    FROM capability_runs AS runs
                    JOIN invocation_payloads AS payloads
                        ON payloads.run_id = runs.run_id
                    ORDER BY runs.completed_at DESC, runs.run_id DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
                ).fetchall()
                total = connection.execute(
                    "SELECT COUNT(*) FROM capability_runs"
                ).fetchone()[0]
                count_rows = connection.execute(
                    """
                    SELECT terminal_state, COUNT(*) AS count
                    FROM capability_runs
                    GROUP BY terminal_state
                    """
                ).fetchall()
        except (OSError, sqlite3.Error) as exc:
            raise PersistenceError("Unable to list durable run storage.") from exc

        try:
            items = tuple(
                RunSummary(
                    run_id=row["run_id"],
                    result_id=row["result_id"],
                    correlation_id=row["correlation_id"],
                    status=row["status"],
                    terminal_state=row["terminal_state"],
                    outcome_reason_code=row["outcome_reason_code"],
                    vulnerability_id=row["vulnerability_id"],
                    target_technology=row["target_technology"],
                    artifact_type=row["artifact_type"],
                    started_at=row["started_at"],
                    completed_at=row["completed_at"],
                    result_href=f"/v1/results/{row['result_id']}",
                )
                for row in rows
            )
        except ValueError as exc:
            raise PersistenceError("Stored run summary failed validation.") from exc
        return RunSummaryPage(
            items=items,
            total=total,
            terminal_state_counts={
                row["terminal_state"]: row["count"] for row in count_rows
            },
        )

    def _get_result_envelope(
        self, where_clause: str, value: str
    ) -> ResultEnvelope | None:
        self.initialize()
        try:
            with self._connect() as connection:
                row = connection.execute(
                    f"""
                    SELECT payloads.result_json
                    FROM capability_runs AS runs
                    JOIN invocation_payloads AS payloads ON payloads.run_id = runs.run_id
                    WHERE {where_clause}
                    """,
                    (value,),
                ).fetchone()
        except (OSError, sqlite3.Error) as exc:
            raise PersistenceError("Unable to read durable run storage.") from exc
        if row is None:
            return None
        try:
            return ResultEnvelope.model_validate_json(row["result_json"])
        except ValueError as exc:
            raise PersistenceError("Stored result failed contract validation.") from exc

    def get_by_idempotency_key(self, key: str) -> IdempotencyRecord | None:
        self.initialize()
        try:
            with self._connect() as connection:
                row = connection.execute(
                    """
                    SELECT runs.request_hash, payloads.result_json
                    FROM capability_runs AS runs
                    JOIN invocation_payloads AS payloads ON payloads.run_id = runs.run_id
                    WHERE runs.idempotency_key = ?
                    """,
                    (key,),
                ).fetchone()
        except (OSError, sqlite3.Error) as exc:
            raise PersistenceError("Unable to read idempotency state.") from exc
        if row is None:
            return None
        try:
            result = ResultEnvelope.model_validate_json(row["result_json"])
        except ValueError as exc:
            raise PersistenceError("Stored idempotency result failed validation.") from exc
        return IdempotencyRecord(request_hash=row["request_hash"], result=result)

    def create_lifecycle_run(
        self,
        request: InvokeRequestEnvelope,
        *,
        idempotency_key: str,
        request_digest: str,
        run_id: str | None = None,
        callback: CallbackMetadata | None = None,
    ) -> CreatedLifecycleRun:
        """Atomically bind one idempotency key to one durable queued run."""
        from uuid import uuid4

        self.initialize()
        effective_run_id = run_id or str(uuid4())
        now = _utc_now()
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT * FROM capability_run_lifecycle WHERE idempotency_key = ?",
                    (idempotency_key,),
                ).fetchone()
                if row is not None:
                    if row["request_digest"] != request_digest:
                        raise IdempotencyConflictError(
                            "Idempotency key is already bound to different input."
                        )
                    if callback is not None:
                        stored_callback = (
                            row["callback_url"],
                            row["callback_workflow_id"],
                            row["callback_signal"],
                        )
                        submitted_callback = (
                            callback.callback_url,
                            callback.callback_workflow_id,
                            callback.callback_signal,
                        )
                        if all(value is None for value in stored_callback):
                            connection.execute(
                                """
                                UPDATE capability_run_lifecycle
                                SET callback_url = ?, callback_workflow_id = ?,
                                    callback_signal = ?, updated_at = ?
                                WHERE run_id = ?
                                """,
                                (*submitted_callback, now, row["run_id"]),
                            )
                            self._create_callback_outbox_records(
                                connection, now=now, run_id=row["run_id"]
                            )
                            row = connection.execute(
                                "SELECT * FROM capability_run_lifecycle WHERE run_id = ?",
                                (row["run_id"],),
                            ).fetchone()
                        elif stored_callback != submitted_callback:
                            raise IdempotencyConflictError(
                                "Idempotency key is already bound to different callback metadata."
                            )
                    connection.commit()
                    return CreatedLifecycleRun(
                        run=_lifecycle_from_row(row), created=False
                    )
                connection.execute(
                    """
                    INSERT INTO capability_run_lifecycle (
                        run_id, request_id, correlation_id, idempotency_key,
                        request_digest, request_json, status, progress_phase,
                        progress_message, created_at, accepted_at, updated_at,
                        callback_url, callback_workflow_id, callback_signal
                    ) VALUES (?, ?, ?, ?, ?, ?, 'queued', 'queued', ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
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
                        callback.callback_url if callback else None,
                        callback.callback_workflow_id if callback else None,
                        callback.callback_signal if callback else None,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM capability_run_lifecycle WHERE run_id = ?",
                    (effective_run_id,),
                ).fetchone()
                connection.commit()
        except IdempotencyConflictError:
            raise
        except (OSError, sqlite3.Error) as exc:
            raise PersistenceError("Unable to create durable lifecycle run.") from exc
        assert row is not None
        return CreatedLifecycleRun(run=_lifecycle_from_row(row), created=True)

    def get_lifecycle_run(self, run_id: str) -> LifecycleRun | None:
        self.initialize()
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM capability_run_lifecycle WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
        except (OSError, sqlite3.Error) as exc:
            raise PersistenceError("Unable to read durable lifecycle run.") from exc
        return _lifecycle_from_row(row) if row is not None else None

    def get_lifecycle_result(self, run_id: str) -> dict | None:
        self.initialize()
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT result_json FROM capability_run_lifecycle WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
        except (OSError, sqlite3.Error) as exc:
            raise PersistenceError("Unable to read durable lifecycle result.") from exc
        if row is None or row["result_json"] is None:
            return None
        try:
            return json.loads(row["result_json"])
        except (TypeError, ValueError) as exc:
            raise PersistenceError("Stored lifecycle result is invalid.") from exc

    def claim_lifecycle_run(
        self, *, worker_id: str, lease_seconds: int, max_attempts: int
    ) -> LifecycleRun | None:
        self.initialize()
        now_dt = datetime.now(UTC)
        now = now_dt.isoformat()
        lease = (now_dt + timedelta(seconds=lease_seconds)).isoformat()
        exhausted = RunFailure(
            code="worker_attempts_exhausted",
            detail="Worker lease expired and the bounded attempt limit was reached.",
            retryable=False,
        ).model_dump_json()
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    """
                    UPDATE capability_run_lifecycle
                    SET status = 'canceled', terminal_state = 'canceled',
                        progress_phase = 'canceled', progress_message = ?,
                        completed_at = ?, updated_at = ?, worker_id = NULL,
                        lease_expires_at = NULL
                                        WHERE status = 'running' AND cancel_requested = 1
                                            AND publication_state IN ('none', 'prepared')
                      AND lease_expires_at < ?
                    """,
                    ("Cancellation completed after worker lease expiry.", now, now, now),
                )
                connection.execute(
                    """
                    UPDATE capability_run_lifecycle
                    SET status = 'failed', terminal_state = 'malfunction',
                        failure_json = ?, progress_phase = 'failed',
                        progress_message = ?, completed_at = ?, updated_at = ?,
                        worker_id = NULL, lease_expires_at = NULL
                                        WHERE status = 'running' AND cancel_requested = 0
                                            AND publication_state != 'publication-pending'
                      AND lease_expires_at < ? AND attempt_number >= ?
                    """,
                    (
                        exhausted,
                        "Worker attempts exhausted.",
                        now,
                        now,
                        now,
                        max_attempts,
                    ),
                )
                self._create_callback_outbox_records(connection, now=now)
                row = connection.execute(
                    """
                    SELECT * FROM capability_run_lifecycle
                                        WHERE (
                                                publication_state = 'publication-pending'
                                                AND status = 'running' AND lease_expires_at < ?
                                            ) OR (
                                                cancel_requested = 0 AND attempt_number < ?
                                                AND (
                                                    status = 'queued'
                                                    OR (status = 'running' AND lease_expires_at < ?)
                                                )
                                            )
                    ORDER BY created_at, run_id
                    LIMIT 1
                    """,
                                        (now, max_attempts, now),
                ).fetchone()
                if row is None:
                    connection.commit()
                    return None
                started_at = row["started_at"] or now
                updated = connection.execute(
                    """
                    UPDATE capability_run_lifecycle
                    SET status = 'running', worker_id = ?, lease_expires_at = ?,
                        last_heartbeat_at = ?, attempt_number = attempt_number + 1,
                        started_at = ?, updated_at = ?, progress_phase = 'translating',
                        progress_message = ?
                                        WHERE run_id = ?
                                            AND (cancel_requested = 0 OR publication_state = 'publication-pending')
                                            AND (status = 'queued' OR lease_expires_at < ?)
                    """,
                    (
                        worker_id,
                        lease,
                        now,
                        started_at,
                        now,
                        "Translation is running.",
                        row["run_id"],
                        now,
                    ),
                )
                if updated.rowcount != 1:
                    connection.rollback()
                    return None
                claimed = connection.execute(
                    "SELECT * FROM capability_run_lifecycle WHERE run_id = ?",
                    (row["run_id"],),
                ).fetchone()
                connection.commit()
        except (OSError, sqlite3.Error) as exc:
            raise PersistenceError("Unable to claim durable lifecycle run.") from exc
        assert claimed is not None
        return _lifecycle_from_row(claimed)

    def heartbeat_lifecycle_run(
        self,
        run_id: str,
        *,
        worker_id: str,
        attempt_number: int,
        lease_seconds: int,
    ) -> bool:
        now_dt = datetime.now(UTC)
        now = now_dt.isoformat()
        lease = (now_dt + timedelta(seconds=lease_seconds)).isoformat()
        try:
            with self._connect() as connection:
                updated = connection.execute(
                    """
                    UPDATE capability_run_lifecycle
                    SET lease_expires_at = ?, last_heartbeat_at = ?, updated_at = ?
                                        WHERE run_id = ? AND status = 'running' AND worker_id = ?
                                            AND attempt_number = ?
                    """,
                                        (lease, now, now, run_id, worker_id, attempt_number),
                )
                connection.commit()
                return updated.rowcount == 1
        except (OSError, sqlite3.Error) as exc:
            raise PersistenceError("Unable to heartbeat durable lifecycle run.") from exc

    def prepare_lifecycle_publication(
        self,
        run_id: str,
        *,
        worker_id: str,
        attempt_number: int,
        result_envelope: ResultEnvelope,
        canonical_result: dict,
        completion: dict,
        request_hash: str,
        started_at: datetime,
        result_id: str,
        terminal_state: str,
    ) -> bool:
        """Fence and durably stage exact output before any external write."""
        now = _utc_now()
        try:
            with self._connect() as connection:
                updated = connection.execute(
                    """
                    UPDATE capability_run_lifecycle
                    SET publication_state = 'prepared',
                        prepared_result_envelope_json = ?, prepared_result_json = ?,
                        prepared_completion_json = ?, prepared_request_hash = ?,
                        prepared_started_at = ?, prepared_result_id = ?,
                        prepared_terminal_state = ?, progress_phase = 'publishing',
                        progress_message = ?, updated_at = ?
                    WHERE run_id = ? AND status = 'running' AND worker_id = ?
                      AND attempt_number = ? AND cancel_requested = 0
                                            AND publication_state = 'none' AND lease_expires_at >= ?
                    """,
                    (
                        result_envelope.model_dump_json(),
                        json.dumps(canonical_result, separators=(",", ":"), ensure_ascii=False),
                        json.dumps(completion, separators=(",", ":"), ensure_ascii=False),
                        request_hash,
                        started_at.astimezone(UTC).isoformat(),
                        result_id,
                        terminal_state,
                        "Result is prepared for durable publication.",
                        now,
                        run_id,
                        worker_id,
                        attempt_number,
                        now,
                    ),
                )
                connection.commit()
                return updated.rowcount == 1
        except (OSError, sqlite3.Error) as exc:
            raise PersistenceError("Unable to prepare durable result publication.") from exc

    def get_prepared_publication(self, run_id: str) -> PreparedPublication | None:
        self.initialize()
        try:
            with self._connect() as connection:
                row = connection.execute(
                    "SELECT * FROM capability_run_lifecycle WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
        except (OSError, sqlite3.Error) as exc:
            raise PersistenceError("Unable to read prepared result publication.") from exc
        if row is None or row["publication_state"] == "none":
            return None
        try:
            return PreparedPublication(
                request=InvokeRequestEnvelope.model_validate_json(row["request_json"]),
                result_envelope=ResultEnvelope.model_validate_json(
                    row["prepared_result_envelope_json"]
                ),
                canonical_result=json.loads(row["prepared_result_json"]),
                completion=json.loads(row["prepared_completion_json"]),
                request_hash=row["prepared_request_hash"],
                started_at=datetime.fromisoformat(row["prepared_started_at"]),
                result_id=row["prepared_result_id"],
                terminal_state=row["prepared_terminal_state"],
                publication_state=row["publication_state"],
            )
        except (TypeError, ValueError) as exc:
            raise PersistenceError("Prepared result publication failed validation.") from exc

    def begin_lifecycle_publication(
        self,
        run_id: str,
        *,
        worker_id: str,
        attempt_number: int,
    ) -> bool:
        """Atomically establish the cutoff after which completion beats cancel."""
        now = _utc_now()
        try:
            with self._connect() as connection:
                updated = connection.execute(
                    """
                    UPDATE capability_run_lifecycle
                    SET publication_state = 'publication-pending', updated_at = ?,
                        progress_message = ?
                    WHERE run_id = ? AND status = 'running' AND worker_id = ?
                      AND attempt_number = ? AND cancel_requested = 0
                                            AND publication_state = 'prepared' AND lease_expires_at >= ?
                    """,
                    (
                        now,
                        "Result publication is pending verification.",
                        run_id,
                        worker_id,
                        attempt_number,
                        now,
                    ),
                )
                if updated.rowcount == 0:
                    row = connection.execute(
                        """
                        SELECT publication_state FROM capability_run_lifecycle
                        WHERE run_id = ? AND status = 'running' AND worker_id = ?
                                                    AND attempt_number = ? AND lease_expires_at >= ?
                        """,
                        (run_id, worker_id, attempt_number, now),
                    ).fetchone()
                    connection.commit()
                    return row is not None and row["publication_state"] == "publication-pending"
                connection.commit()
                return True
        except (OSError, sqlite3.Error) as exc:
            raise PersistenceError("Unable to begin durable result publication.") from exc

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
        now = _utc_now()
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                canceled = connection.execute(
                    """
                    UPDATE capability_run_lifecycle
                    SET status = 'canceled', terminal_state = 'canceled',
                        progress_phase = 'canceled', progress_message = ?,
                        completed_at = ?, updated_at = ?, worker_id = NULL,
                        lease_expires_at = NULL
                    WHERE run_id = ? AND status = 'running' AND worker_id = ?
                                            AND attempt_number = ?
                      AND cancel_requested = 1
                      AND publication_state != 'publication-pending'
                    """,
                                        (
                                                "Cancellation completed.",
                                                now,
                                                now,
                                                run_id,
                                                worker_id,
                                                attempt_number,
                                        ),
                )
                if canceled.rowcount == 1:
                    self._create_callback_outbox_records(
                        connection, now=now, run_id=run_id
                    )
                    connection.commit()
                    return False
                updated = connection.execute(
                    """
                    UPDATE capability_run_lifecycle
                    SET status = 'completed', terminal_state = ?, result_id = ?,
                        result_json = ?, completion_json = ?, progress_phase = 'completed',
                        progress_percent = 100, progress_message = ?, completed_at = ?,
                        updated_at = ?, worker_id = NULL, lease_expires_at = NULL,
                        publication_state = CASE
                            WHEN publication_state = 'publication-pending' THEN 'published'
                            ELSE publication_state
                        END
                    WHERE run_id = ? AND status = 'running' AND worker_id = ?
                                            AND attempt_number = ?
                      AND result_json IS NULL
                      AND (cancel_requested = 0 OR publication_state = 'publication-pending')
                      AND lease_expires_at >= ?
                    """,
                    (
                        terminal_state,
                        result_id,
                        json.dumps(result, separators=(",", ":"), ensure_ascii=False),
                        json.dumps(completion, separators=(",", ":"), ensure_ascii=False),
                        "Translation completed.",
                        now,
                        now,
                        run_id,
                        worker_id,
                        attempt_number,
                        now,
                    ),
                )
                if updated.rowcount == 1:
                    self._create_callback_outbox_records(
                        connection, now=now, run_id=run_id
                    )
                connection.commit()
                return updated.rowcount == 1
        except (OSError, sqlite3.Error) as exc:
            raise PersistenceError("Unable to complete durable lifecycle run.") from exc

    def fail_lifecycle_run(
        self,
        run_id: str,
        *,
        worker_id: str,
        attempt_number: int,
        failure: RunFailure,
        result: dict | None = None,
    ) -> bool:
        now = _utc_now()
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                updated = connection.execute(
                    """
                    UPDATE capability_run_lifecycle
                    SET status = CASE
                            WHEN publication_state = 'publication-pending' THEN 'failed'
                            WHEN cancel_requested = 1 THEN 'canceled' ELSE 'failed'
                        END,
                        terminal_state = CASE
                            WHEN publication_state = 'publication-pending' THEN 'malfunction'
                            WHEN cancel_requested = 1 THEN 'canceled' ELSE 'malfunction'
                        END,
                        failure_json = CASE
                            WHEN publication_state != 'publication-pending' AND cancel_requested = 1
                            THEN NULL ELSE ?
                        END,
                        result_json = CASE
                            WHEN publication_state != 'publication-pending' AND cancel_requested = 1
                            THEN NULL ELSE ?
                        END,
                        completion_json = CASE
                            WHEN publication_state = 'publication-pending'
                            THEN prepared_completion_json ELSE completion_json
                        END,
                        progress_phase = CASE
                            WHEN publication_state != 'publication-pending' AND cancel_requested = 1
                            THEN 'canceled' ELSE 'failed'
                        END,
                        progress_message = CASE
                            WHEN publication_state != 'publication-pending' AND cancel_requested = 1
                            THEN ? ELSE ?
                        END,
                        completed_at = ?, updated_at = ?, worker_id = NULL,
                        lease_expires_at = NULL,
                        publication_state = CASE
                            WHEN publication_state = 'publication-pending' THEN 'published'
                            ELSE publication_state
                        END
                                        WHERE run_id = ? AND status = 'running' AND worker_id = ?
                                            AND attempt_number = ?
                                            AND (
                                                publication_state != 'publication-pending'
                                                OR lease_expires_at >= ?
                                            )
                    """,
                    (
                        failure.model_dump_json(),
                        (
                            json.dumps(result, separators=(",", ":"), ensure_ascii=False)
                            if result is not None
                            else None
                        ),
                        "Cancellation completed.",
                        failure.detail,
                        now,
                        now,
                        run_id,
                        worker_id,
                        attempt_number,
                        now,
                    ),
                )
                if updated.rowcount == 1:
                    self._create_callback_outbox_records(
                        connection, now=now, run_id=run_id
                    )
                connection.commit()
                return updated.rowcount == 1
        except (OSError, sqlite3.Error) as exc:
            raise PersistenceError("Unable to fail durable lifecycle run.") from exc

    def cancel_lifecycle_run(self, run_id: str) -> LifecycleRun | None:
        now = _utc_now()
        try:
            with self._connect() as connection:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT status, publication_state FROM capability_run_lifecycle WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                if row is None:
                    connection.commit()
                    return None
                if row["status"] == "queued":
                    connection.execute(
                        """
                        UPDATE capability_run_lifecycle
                        SET status = 'canceled', terminal_state = 'canceled',
                            cancel_requested = 1, progress_phase = 'canceled',
                            progress_message = ?, completed_at = ?, updated_at = ?
                        WHERE run_id = ?
                        """,
                        ("Run canceled before execution.", now, now, run_id),
                    )
                elif row["status"] == "running" and row["publication_state"] in {
                    "none",
                    "prepared",
                }:
                    connection.execute(
                        """
                        UPDATE capability_run_lifecycle
                        SET status = 'canceled', terminal_state = 'canceled',
                            cancel_requested = 1, progress_phase = 'canceled',
                            progress_message = ?, completed_at = ?, updated_at = ?,
                            worker_id = NULL, lease_expires_at = NULL
                        WHERE run_id = ?
                        """,
                        ("Cancellation completed.", now, now, run_id),
                    )
                elif row["status"] == "running":
                    connection.execute(
                        """
                        UPDATE capability_run_lifecycle
                        SET cancel_requested = 1, progress_message = ?, updated_at = ?
                        WHERE run_id = ? AND status = 'running'
                          AND publication_state = 'publication-pending'
                        """,
                        (
                            "Cancellation arrived after publication began; canonical completion is pending.",
                            now,
                            run_id,
                        ),
                    )
                self._create_callback_outbox_records(
                    connection, now=now, run_id=run_id
                )
                current = connection.execute(
                    "SELECT * FROM capability_run_lifecycle WHERE run_id = ?",
                    (run_id,),
                ).fetchone()
                connection.commit()
        except (OSError, sqlite3.Error) as exc:
            raise PersistenceError("Unable to cancel durable lifecycle run.") from exc
        assert current is not None
        return _lifecycle_from_row(current)

    def list_due_callback_deliveries(
        self, *, now: datetime, limit: int
    ) -> tuple[CallbackDelivery, ...]:
        self.initialize()
        try:
            with self._connect() as connection:
                rows = connection.execute(
                    """
                    SELECT * FROM callback_deliveries
                    WHERE delivery_status IN ('pending', 'retry')
                      AND next_attempt_at <= ?
                    ORDER BY next_attempt_at, created_at, event_id
                    LIMIT ?
                    """,
                    (now.astimezone(UTC).isoformat(), limit),
                ).fetchall()
        except (OSError, sqlite3.Error) as exc:
            raise PersistenceError("Unable to list due callback deliveries.") from exc
        return tuple(_callback_delivery_from_row(row) for row in rows)

    def mark_callback_delivered(
        self, event_id: str, *, delivered_at: datetime, status_code: int
    ) -> None:
        timestamp = delivered_at.astimezone(UTC).isoformat()
        self._update_callback_delivery(
            event_id,
            """
            UPDATE callback_deliveries
            SET delivery_status = 'delivered', attempts = attempts + 1,
                delivered_at = ?, last_status_code = ?, last_error_category = NULL,
                updated_at = ?
            WHERE event_id = ? AND delivery_status IN ('pending', 'retry')
            """,
            (timestamp, status_code, timestamp, event_id),
        )

    def reschedule_callback_delivery(
        self,
        event_id: str,
        *,
        attempts: int,
        next_attempt_at: datetime,
        status_code: int | None,
        error_category: str,
    ) -> None:
        timestamp = datetime.now(UTC).isoformat()
        self._update_callback_delivery(
            event_id,
            """
            UPDATE callback_deliveries
            SET delivery_status = 'retry', attempts = ?, next_attempt_at = ?,
                last_status_code = ?, last_error_category = ?, updated_at = ?
            WHERE event_id = ? AND delivery_status IN ('pending', 'retry')
            """,
            (
                attempts,
                next_attempt_at.astimezone(UTC).isoformat(),
                status_code,
                error_category,
                timestamp,
                event_id,
            ),
        )

    def mark_callback_configuration_failed(
        self,
        event_id: str,
        *,
        attempts: int,
        failed_at: datetime,
        status_code: int | None,
        error_category: str,
    ) -> None:
        timestamp = failed_at.astimezone(UTC).isoformat()
        self._update_callback_delivery(
            event_id,
            """
            UPDATE callback_deliveries
            SET delivery_status = 'configuration-failed', attempts = ?,
                configuration_failed_at = ?, last_status_code = ?,
                last_error_category = ?, updated_at = ?
            WHERE event_id = ? AND delivery_status IN ('pending', 'retry')
            """,
            (attempts, timestamp, status_code, error_category, timestamp, event_id),
        )

    def _update_callback_delivery(
        self, event_id: str, statement: str, parameters: tuple
    ) -> None:
        del event_id
        self.initialize()
        try:
            with self._connect() as connection:
                connection.execute(statement, parameters)
                connection.commit()
        except (OSError, sqlite3.Error) as exc:
            raise PersistenceError("Unable to update callback delivery state.") from exc

    @staticmethod
    def _create_callback_outbox_records(
        connection: sqlite3.Connection, *, now: str, run_id: str | None = None
    ) -> None:
        run_filter = "AND run_id = ?" if run_id is not None else ""
        parameters: tuple[str, ...] = (now, now, now) + (
            (run_id,) if run_id else ()
        )
        connection.execute(
            f"""
            INSERT OR IGNORE INTO callback_deliveries (
                event_id, run_id, callback_url, callback_workflow_id,
                callback_signal, capability, request_id, correlation_id,
                terminal_status, delivery_status, attempts, next_attempt_at,
                created_at, updated_at
            )
            SELECT 'control-translation:' || run_id || ':terminal:v1', run_id,
                callback_url, callback_workflow_id, callback_signal,
                'control-translation', request_id, correlation_id, status,
                'pending', 0, ?, ?, ?
            FROM capability_run_lifecycle
            WHERE status IN ('completed', 'failed', 'canceled')
              AND callback_url IS NOT NULL
              AND callback_workflow_id IS NOT NULL
              AND callback_signal IS NOT NULL
              {run_filter}
            """,
            parameters,
        )


def _utc_now() -> str:
    return datetime.now(UTC).isoformat()


def _lifecycle_from_row(row: sqlite3.Row) -> LifecycleRun:
    try:
        request = InvokeRequestEnvelope.model_validate_json(row["request_json"])
        failure = (
            RunFailure.model_validate_json(row["failure_json"])
            if row["failure_json"]
            else None
        )
        completion = json.loads(row["completion_json"]) if row["completion_json"] else None
        status = CapabilityRunStatus(
            request_id=row["request_id"],
            correlation_id=row["correlation_id"],
            run_id=row["run_id"],
            status=row["status"],
            terminal_state=row["terminal_state"],
            result_id=row["result_id"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            updated_at=row["updated_at"],
            completed_at=row["completed_at"],
            progress=RunProgress(
                phase=row["progress_phase"],
                percent=row["progress_percent"],
                message=row["progress_message"],
            ),
            failure=failure,
            completion=completion,
        )
    except (TypeError, ValueError) as exc:
        raise PersistenceError("Stored lifecycle run failed validation.") from exc
    return LifecycleRun(
        request=request,
        status=status,
        request_digest=row["request_digest"],
        cancel_requested=bool(row["cancel_requested"]),
        worker_id=row["worker_id"],
        attempt_number=row["attempt_number"],
        publication_state=row["publication_state"],
        callback=(
            CallbackMetadata(
                callback_url=row["callback_url"],
                callback_workflow_id=row["callback_workflow_id"],
                callback_signal=row["callback_signal"],
            )
            if row["callback_url"]
            else None
        ),
    )


def _callback_delivery_from_row(row: sqlite3.Row) -> CallbackDelivery:
    return CallbackDelivery(
        event_id=row["event_id"],
        callback_url=row["callback_url"],
        callback_workflow_id=row["callback_workflow_id"],
        callback_signal=row["callback_signal"],
        capability=row["capability"],
        request_id=row["request_id"],
        correlation_id=row["correlation_id"],
        run_id=row["run_id"],
        terminal_status=row["terminal_status"],
        attempts=row["attempts"],
        next_attempt_at=datetime.fromisoformat(row["next_attempt_at"]),
    )
