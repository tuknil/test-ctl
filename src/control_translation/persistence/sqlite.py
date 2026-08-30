"""Secure, transaction-oriented SQLite persistence for capability runs."""

from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

from control_translation.contracts import InvokeRequestEnvelope, ResultEnvelope, RunSummary
from control_translation.persistence.base import (
    IdempotencyRecord,
    PersistenceError,
    RunSummaryPage,
)
from control_translation.persistence.migrations import MIGRATIONS


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
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute("PRAGMA synchronous = NORMAL")
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
            return False

    def save_completed_run(
        self,
        request: InvokeRequestEnvelope,
        result: ResultEnvelope,
        *,
        request_hash: str,
        started_at: datetime,
    ) -> None:
        self.initialize()
        structured = result.structured_result
        completed_at = structured.produced_at.astimezone(timezone.utc).isoformat()
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
                        started_at.astimezone(timezone.utc).isoformat(),
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


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()
