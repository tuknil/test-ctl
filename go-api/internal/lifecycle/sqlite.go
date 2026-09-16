// Package lifecycle is the durable queue for asynchronous translation runs.
//
// It is the one piece of local state this service keeps. Completed results
// live in Databricks; SQLite exists only to coordinate work — which run is
// queued, which worker holds it, and how many attempts it has had — because a
// Delta table has no row locks and makes a poor queue. This mirrors the Python
// service, which also keeps lifecycle coordination in SQLite while sending
// completed results to Databricks.
//
// The file is written by exactly one replica (SERVICE_REPLICA_COUNT, enforced
// at readiness). Mount it on durable storage: a lost file means in-flight runs
// are forgotten, though any result already written to Databricks survives.
package lifecycle

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// ErrStore reports that the lifecycle queue could not complete an operation.
var ErrStore = errors.New("durable lifecycle storage is unavailable")

// ErrIdempotencyConflict reports a key reused for different semantic input.
var ErrIdempotencyConflict = errors.New("idempotency key was already used for a different request")

func storeError(operation string, cause error) error {
	return fmt.Errorf("%w: %s: %v", ErrStore, operation, cause)
}

const timeLayout = "2006-01-02T15:04:05.000000Z"

func nowText() string { return time.Now().UTC().Format(timeLayout) }

// Store is the SQLite-backed lifecycle queue.
type Store struct {
	db *sql.DB
}

// Open prepares the database file and applies the schema.
func Open(databasePath string) (*Store, error) {
	if directory := filepath.Dir(databasePath); directory != "" && directory != "." {
		if err := os.MkdirAll(directory, 0o750); err != nil {
			return nil, storeError("create-database-directory", err)
		}
	}
	// DELETE journaling and FULL synchronous match the Python service's
	// single-writer durable volume model; WAL is not safe for that mount.
	dsn := databasePath + "?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)" +
		"&_pragma=journal_mode(DELETE)&_pragma=synchronous(FULL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, storeError("open-database", err)
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		return nil, err
	}
	// Owner-only permissions are best effort on hosts without POSIX modes.
	_ = os.Chmod(databasePath, 0o600)
	return store, nil
}

// Close releases the database handle.
func (s *Store) Close() error { return s.db.Close() }

// Healthcheck reports whether the queue is reachable, for GET /ready.
func (s *Store) Healthcheck() bool {
	var value int
	return s.db.QueryRow("SELECT 1").Scan(&value) == nil
}

// The schema and its bookkeeping match migration 2 of
// src/control_translation/persistence/migrations.py, so a database created by
// either service is readable by the other.
const lifecycleSchema = `
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
		completion_json TEXT CHECK (completion_json IS NULL OR json_valid(completion_json)),
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
`

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			name TEXT NOT NULL,
			applied_at TEXT NOT NULL
		)`); err != nil {
		return storeError("create-schema-migrations", err)
	}
	const version, name = 2, "async_capability_lifecycle"
	var applied int
	err := s.db.QueryRow("SELECT 1 FROM schema_migrations WHERE version = ?", version).Scan(&applied)
	if err == nil {
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return storeError("read-schema-migrations", err)
	}
	transaction, err := s.db.Begin()
	if err != nil {
		return storeError("begin-migration", err)
	}
	if _, err := transaction.Exec(lifecycleSchema); err != nil {
		_ = transaction.Rollback()
		return storeError("apply-migration", err)
	}
	if _, err := transaction.Exec(
		"INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)",
		version, name, nowText()); err != nil {
		_ = transaction.Rollback()
		return storeError("record-migration", err)
	}
	if err := transaction.Commit(); err != nil {
		return storeError("commit-migration", err)
	}
	return nil
}
