// Package lifecycle is the durable queue for asynchronous translation runs.
//
// It is the one piece of state this service keeps outside Databricks.
// Completed results live in Databricks; Postgres exists only to coordinate
// work -- which run is queued, which worker holds it, and how many attempts it
// has had -- because a Delta table has no row locks and makes a poor queue.
//
// The queue is shared: runs are claimed with FOR UPDATE SKIP LOCKED, so any
// number of replicas can poll it without two of them claiming the same run.
package lifecycle

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/ATT-CSO/control-translation/go-api/internal/config"
)

// ErrStore reports that the lifecycle queue could not complete an operation.
var ErrStore = errors.New("durable lifecycle storage is unavailable")

// ErrIdempotencyConflict reports a key reused for different semantic input.
var ErrIdempotencyConflict = errors.New("idempotency key was already used for a different request")

func storeError(operation string, cause error) error {
	return fmt.Errorf("%w: %s: %v", ErrStore, operation, cause)
}

// Store is the Postgres-backed lifecycle queue.
type Store struct {
	db   *sql.DB
	pool *pgxpool.Pool
}

// Open connects to the lifecycle database named by DATABASE_URL.
func Open(settings config.Settings) (*Store, error) {
	return OpenConnectionString(settings.DatabaseURL)
}

// OpenConnectionString connects using a Postgres URL. It is what Open does,
// exposed for tests and for anything holding a URL rather than settings.
func OpenConnectionString(rawURL string) (*Store, error) {
	poolConfig, err := pgxpool.ParseConfig(connectionString(rawURL))
	if err != nil {
		return nil, storeError("parse-database-url", err)
	}
	poolConfig.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, storeError("open-database", err)
	}

	store := &Store{db: stdlib.OpenDBFromPool(pool), pool: pool}
	if err := store.migrate(); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

// connectionString is DATABASE_URL with the one addition worth making: an
// application_name, so a session holding a queue lock is identifiable in
// pg_stat_activity. Everything else is left exactly as the operator wrote it,
// including any application_name they chose themselves.
func connectionString(rawURL string) string {
	raw := strings.TrimSpace(rawURL)
	parsed, err := url.Parse(raw)
	if err != nil {
		// Configuration validation already reports a malformed URL. Pass it
		// through so the driver produces the error rather than this returning
		// a half-built string.
		return raw
	}
	query := parsed.Query()
	if query.Get("application_name") == "" {
		query.Set("application_name", "control-translation-go")
		parsed.RawQuery = query.Encode()
	}
	return parsed.String()
}

// Close releases the pool.
func (s *Store) Close() error {
	err := s.db.Close()
	s.pool.Close()
	return err
}

// Healthcheck reports whether the queue is reachable, for GET /ready.
func (s *Store) Healthcheck() bool {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var value int
	return s.db.QueryRowContext(ctx, "SELECT 1").Scan(&value) == nil
}

// The queue table. Types are Postgres's own rather than the SQLite
// translations they replace: timestamptz instead of text timestamps, boolean
// instead of 0/1, and jsonb instead of text with a json_valid() check, so
// malformed JSON is rejected by the column type.
const lifecycleSchema = `
	CREATE TABLE IF NOT EXISTS capability_run_lifecycle (
		run_id TEXT PRIMARY KEY,
		request_id TEXT NOT NULL,
		correlation_id TEXT NOT NULL,
		idempotency_key TEXT NOT NULL UNIQUE,
		request_digest TEXT NOT NULL,
		request_json JSONB NOT NULL,
		status TEXT NOT NULL CHECK (
			status IN ('queued', 'running', 'completed', 'failed', 'canceled')
		),
		terminal_state TEXT,
		result_id TEXT UNIQUE,
		result_json JSONB,
		completion_json JSONB,
		failure_json JSONB,
		progress_phase TEXT NOT NULL,
		progress_percent INTEGER,
		progress_message TEXT NOT NULL,
		cancel_requested BOOLEAN NOT NULL DEFAULT FALSE,
		worker_id TEXT,
		lease_expires_at TIMESTAMPTZ,
		last_heartbeat_at TIMESTAMPTZ,
		attempt_number INTEGER NOT NULL DEFAULT 0,
		created_at TIMESTAMPTZ NOT NULL,
		accepted_at TIMESTAMPTZ NOT NULL,
		started_at TIMESTAMPTZ,
		updated_at TIMESTAMPTZ NOT NULL,
		completed_at TIMESTAMPTZ
	);
	CREATE INDEX IF NOT EXISTS ix_capability_run_lifecycle_status_lease
		ON capability_run_lifecycle(status, lease_expires_at, created_at);
	CREATE INDEX IF NOT EXISTS ix_capability_run_lifecycle_correlation
		ON capability_run_lifecycle(correlation_id);
`

// migrate readies the schema, and needs no setting to say whether it may.
//
// It tries to create the table. When that fails because the connecting role
// holds no DDL rights -- a managed database whose schema is applied by someone
// else -- the table is already there and there is nothing to do, so the
// failure only matters if the table really is absent. That covers both
// postures without asking the operator which one they are in.
func (s *Store) migrate() error {
	if _, err := s.db.Exec(lifecycleSchema); err != nil {
		if present, checkErr := s.schemaPresent(); checkErr == nil && present {
			return nil
		}
		return storeError("apply-migration", err)
	}
	return nil
}

func (s *Store) schemaPresent() (bool, error) {
	var present bool
	err := s.db.QueryRow(`SELECT to_regclass('capability_run_lifecycle') IS NOT NULL`).Scan(&present)
	return present, err
}

// isUniqueViolation reports a duplicate key, which the queue treats as a
// concurrent insert of the same idempotency key rather than an error.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
