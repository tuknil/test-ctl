"""Ordered, immutable SQLite schema migrations."""

from __future__ import annotations


MIGRATIONS: tuple[tuple[int, str, str], ...] = (
    (
        1,
        "initial_persistence_schema",
        """
        CREATE TABLE capability_runs (
            run_id TEXT PRIMARY KEY,
            capability TEXT NOT NULL,
            contract_id TEXT NOT NULL,
            request_id TEXT,
            correlation_id TEXT NOT NULL,
            idempotency_key TEXT,
            request_hash TEXT NOT NULL,
            result_id TEXT NOT NULL UNIQUE,
            status TEXT NOT NULL CHECK (status IN ('succeeded', 'declined', 'malfunction')),
            terminal_state TEXT NOT NULL CHECK (
                terminal_state IN (
                    'translated', 'cannot-express', 'insufficient-context',
                    'scope-declined', 'malfunction'
                )
            ),
            outcome_reason_code TEXT NOT NULL,
            started_at TEXT NOT NULL,
            completed_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE UNIQUE INDEX ux_capability_runs_idempotency_key
            ON capability_runs(idempotency_key)
            WHERE idempotency_key IS NOT NULL;
        CREATE INDEX ix_capability_runs_correlation_id
            ON capability_runs(correlation_id);
        CREATE INDEX ix_capability_runs_request_id
            ON capability_runs(request_id);
        CREATE INDEX ix_capability_runs_terminal_state
            ON capability_runs(terminal_state);
        CREATE INDEX ix_capability_runs_completed_at
            ON capability_runs(completed_at);

        CREATE TABLE invocation_payloads (
            run_id TEXT PRIMARY KEY,
            request_json TEXT NOT NULL CHECK (json_valid(request_json)),
            result_json TEXT NOT NULL CHECK (json_valid(result_json)),
            prose_summary TEXT NOT NULL,
            inference_json TEXT NOT NULL CHECK (json_valid(inference_json)),
            warnings_json TEXT NOT NULL CHECK (json_valid(warnings_json)),
            trace_json TEXT NOT NULL CHECK (json_valid(trace_json)),
            FOREIGN KEY (run_id) REFERENCES capability_runs(run_id) ON DELETE CASCADE
        );

        CREATE TABLE result_artifacts (
            run_id TEXT NOT NULL,
            artifact_id TEXT NOT NULL,
            result_id TEXT NOT NULL,
            artifact_type TEXT NOT NULL,
            content TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            emitted_as TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY (run_id, artifact_id),
            FOREIGN KEY (run_id) REFERENCES capability_runs(run_id) ON DELETE CASCADE
        );
        CREATE INDEX ix_result_artifacts_result_id
            ON result_artifacts(result_id);
        CREATE INDEX ix_result_artifacts_content_hash
            ON result_artifacts(content_hash);

        CREATE TABLE evidence_references (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id TEXT NOT NULL,
            result_id TEXT NOT NULL,
            claim TEXT NOT NULL,
            evidence_ref TEXT NOT NULL,
            created_at TEXT NOT NULL,
            UNIQUE (run_id, claim, evidence_ref),
            FOREIGN KEY (run_id) REFERENCES capability_runs(run_id) ON DELETE CASCADE
        );
        CREATE INDEX ix_evidence_references_result_id
            ON evidence_references(result_id);
        """,
    ),
)
