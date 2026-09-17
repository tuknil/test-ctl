// Package lifecycle is the durable queue for asynchronous translation runs.
//
// It is the one piece of state this service keeps outside Databricks.
// Completed results live in Databricks; Postgres exists only to coordinate
// work -- which run is queued, which worker holds it, and how many attempts it
// has had -- because a Delta table has no row locks and makes a poor queue.
//
// The deployed database is Azure Database for PostgreSQL, authenticated with
// an Entra access token rather than a password. The queue is shared: runs are
// claimed with FOR UPDATE SKIP LOCKED, so any number of replicas can poll it
// without two of them claiming the same run.
package lifecycle

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"

	"github.com/ATT-CSO/control-translation/go-api/internal/config"
)

// ErrStore reports that the lifecycle queue could not complete an operation.
var ErrStore = errors.New("durable lifecycle storage is unavailable")

// ErrIdempotencyConflict reports a key reused for different semantic input.
var ErrIdempotencyConflict = errors.New("idempotency key was already used for a different request")

// ErrSchemaMissing reports that the queue table is absent and this service is
// not the thing that creates it.
var ErrSchemaMissing = errors.New("lifecycle schema is missing and DATABASE_MIGRATION_MODE is external")

func storeError(operation string, cause error) error {
	return fmt.Errorf("%w: %s: %v", ErrStore, operation, cause)
}

// Store is the Postgres-backed lifecycle queue.
type Store struct {
	db   *sql.DB
	pool *pgxpool.Pool
}

// Open connects to the lifecycle database and readies its schema.
//
// Nothing here is a password: on the Entra path the connection's password is a
// token minted immediately before each connection is made, which is why the
// pool is built from a config with a BeforeConnect hook rather than from a
// connection string.
func Open(settings config.Settings) (*Store, error) {
	return OpenWithTokenSource(settings, tokenSourceFor(settings))
}

// tokenSourceFor picks how the connection password is produced.
//
// On the password path there is nothing to produce: the password is already in
// DATABASE_URL, so no source is returned and the URL is used as given.
func tokenSourceFor(settings config.Settings) TokenSource {
	if settings.DatabaseAuthMode == config.AuthModeEntra {
		return NewEntraTokenSource(
			settings.AzureTenantID, settings.AzureClientID,
			settings.AzureClientSecret, settings.AzurePostgresTokenScope,
		)
	}
	return nil
}

// OpenWithTokenSource is Open with the credential source supplied, which is
// how a caller substitutes a different way of minting the password.
func OpenWithTokenSource(settings config.Settings, tokens TokenSource) (*Store, error) {
	return open(connectionString(settings), settings.DatabaseMigrationMode, tokens)
}

// OpenConnectionString connects using an ordinary Postgres URL, for a local or
// non-Azure database where the password is in the string and no token has to
// be minted. The deployed service does not use this path.
func OpenConnectionString(url, migrationMode string) (*Store, error) {
	return open(url, migrationMode, nil)
}

// open is the one place a pool is built, so every path gets the same lifetimes
// and the same schema handling.
func open(url, migrationMode string, tokens TokenSource) (*Store, error) {
	poolConfig, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, storeError("parse-database-settings", err)
	}

	// A token lives about an hour. Recycling connections well inside that
	// keeps the pool from holding one whose token has since expired.
	poolConfig.MaxConnLifetime = 30 * time.Minute
	poolConfig.MaxConnIdleTime = 5 * time.Minute
	if tokens != nil {
		poolConfig.BeforeConnect = func(ctx context.Context, connConfig *pgx.ConnConfig) error {
			token, err := tokens.Token(ctx)
			if err != nil {
				return err
			}
			connConfig.Password = token
			return nil
		}
	}

	pool, err := pgxpool.NewWithConfig(context.Background(), poolConfig)
	if err != nil {
		return nil, storeError("open-database", err)
	}

	store := &Store{db: stdlib.OpenDBFromPool(pool), pool: pool}
	if err := store.migrate(migrationMode); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

// connectionString is DATABASE_URL, with the one addition worth making: an
// application_name, so a session holding a queue lock is identifiable in
// pg_stat_activity. Anything already in the URL is left alone -- it is the
// operator's string, not a set of parts to reassemble.
//
// On the Entra path any password in the URL is dropped. A token is attached
// per connection instead, and leaving a stale one in place would only produce
// a confusing authentication failure.
func connectionString(settings config.Settings) string {
	raw := strings.TrimSpace(settings.DatabaseURL)
	parsed, err := url.Parse(raw)
	if err != nil {
		// Configuration validation already reports this; pass it through so
		// the driver produces the error rather than this returning a
		// half-built string.
		return raw
	}
	if settings.DatabaseAuthMode == config.AuthModeEntra && parsed.User != nil {
		parsed.User = url.User(parsed.User.Username())
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

// migrate readies the schema, or verifies someone else has.
//
// In the deployed posture DATABASE_MIGRATION_MODE is external: the service's
// principal is not expected to hold DDL rights, so it checks the table exists
// and fails startup loudly if it does not, rather than running CREATE TABLE
// and failing on a permission error that reads like an outage.
func (s *Store) migrate(mode string) error {
	if mode == config.MigrationModeExternal {
		return s.verifySchema()
	}
	if _, err := s.db.Exec(lifecycleSchema); err != nil {
		return storeError("apply-migration", err)
	}
	return nil
}

func (s *Store) verifySchema() error {
	var present bool
	err := s.db.QueryRow(`SELECT to_regclass('capability_run_lifecycle') IS NOT NULL`).Scan(&present)
	if err != nil {
		return storeError("verify-schema", err)
	}
	if !present {
		return ErrSchemaMissing
	}
	return nil
}

// isUniqueViolation reports a duplicate key, which the queue treats as a
// concurrent insert of the same idempotency key rather than an error.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}
