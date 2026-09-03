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
    (
        2,
        "async_capability_lifecycle",
        """
        CREATE TABLE capability_run_lifecycle (
            run_id TEXT PRIMARY KEY,
            request_id TEXT NOT NULL,
            correlation_id TEXT NOT NULL,
            idempotency_key TEXT NOT NULL UNIQUE,
            request_digest TEXT NOT NULL,
            request_json TEXT NOT NULL CHECK (json_valid(request_json)),
            status TEXT NOT NULL CHECK (
                status IN ('queued', 'running', 'completed', 'failed', 'canceled')
            ),
            terminal_state TEXT,
            result_id TEXT UNIQUE,
            result_json TEXT CHECK (result_json IS NULL OR json_valid(result_json)),
            completion_json TEXT CHECK (
                completion_json IS NULL OR json_valid(completion_json)
            ),
            failure_json TEXT CHECK (failure_json IS NULL OR json_valid(failure_json)),
            progress_phase TEXT NOT NULL,
            progress_percent INTEGER,
            progress_message TEXT NOT NULL,
            cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK (cancel_requested IN (0, 1)),
            worker_id TEXT,
            lease_expires_at TEXT,
            last_heartbeat_at TEXT,
            attempt_number INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL,
            accepted_at TEXT NOT NULL,
            started_at TEXT,
            updated_at TEXT NOT NULL,
            completed_at TEXT
        );
        CREATE INDEX ix_capability_run_lifecycle_status_lease
            ON capability_run_lifecycle(status, lease_expires_at, created_at);
        CREATE INDEX ix_capability_run_lifecycle_correlation
            ON capability_run_lifecycle(correlation_id);
        """,
    ),
    (
        3,
        "durable_result_publication_outbox",
        """
        ALTER TABLE capability_run_lifecycle
            ADD COLUMN publication_state TEXT NOT NULL DEFAULT 'none'
            CHECK (publication_state IN ('none', 'prepared', 'publication-pending', 'published'));
        ALTER TABLE capability_run_lifecycle
            ADD COLUMN prepared_result_envelope_json TEXT
            CHECK (
                prepared_result_envelope_json IS NULL
                OR json_valid(prepared_result_envelope_json)
            );
        ALTER TABLE capability_run_lifecycle
            ADD COLUMN prepared_result_json TEXT
            CHECK (prepared_result_json IS NULL OR json_valid(prepared_result_json));
        ALTER TABLE capability_run_lifecycle
            ADD COLUMN prepared_completion_json TEXT
            CHECK (
                prepared_completion_json IS NULL
                OR json_valid(prepared_completion_json)
            );
        ALTER TABLE capability_run_lifecycle ADD COLUMN prepared_request_hash TEXT;
        ALTER TABLE capability_run_lifecycle ADD COLUMN prepared_started_at TEXT;
        ALTER TABLE capability_run_lifecycle ADD COLUMN prepared_result_id TEXT;
        ALTER TABLE capability_run_lifecycle ADD COLUMN prepared_terminal_state TEXT;
        CREATE INDEX ix_capability_run_lifecycle_publication
            ON capability_run_lifecycle(publication_state, status, lease_expires_at);
        """,
    ),
)
