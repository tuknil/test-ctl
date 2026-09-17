// Package lifecycletest gives tests a real Postgres to run the lifecycle
// queue against.
//
// The queue's behaviour is the database's behaviour -- FOR UPDATE SKIP LOCKED,
// unique violations, jsonb rejecting malformed JSON -- so there is no useful
// fake. Tests run against a real server or they do not run.
package lifecycletest

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/ATT-CSO/control-translation/go-api/internal/config"
	"github.com/ATT-CSO/control-translation/go-api/internal/lifecycle"
)

// DefaultURL is where the tests look when TEST_DATABASE_URL is unset. It
// matches the postgres service in docker-compose.yml, so
// `docker compose --profile go up -d postgres` is all the setup there is.
//
// Beware the skip below: a queue suite that skips is a suite that did not run.
// When a change to this package looks green, check that it actually ran.
const DefaultURL = "postgres://control_translation:control_translation" +
	"@127.0.0.1:55432/control_translation?sslmode=disable"

// URL is the server the tests use.
func URL() string {
	if configured := strings.TrimSpace(os.Getenv("TEST_DATABASE_URL")); configured != "" {
		return configured
	}
	return DefaultURL
}

var (
	probeOnce   sync.Once
	probeFailed error
)

// Require skips the test when no Postgres is reachable, naming what to start.
// The probe runs once per process so an unreachable server does not cost every
// test a connection timeout.
func Require(t *testing.T) {
	t.Helper()
	probeOnce.Do(func() {
		db, err := sql.Open("pgx", URL())
		if err != nil {
			probeFailed = err
			return
		}
		defer func() { _ = db.Close() }()
		probeFailed = db.Ping()
	})
	if probeFailed != nil {
		t.Skipf("no test Postgres at %s (%v); see go-api/README.md to start one, "+
			"or set TEST_DATABASE_URL", redact(URL()), probeFailed)
	}
}

// Queue opens a lifecycle store on a schema of its own, dropped when the test
// ends. A schema rather than a shared table so tests cannot see each other's
// runs, and a schema rather than a database because creating one is cheap.
func Queue(t *testing.T) *lifecycle.Store {
	t.Helper()
	Require(t)

	schema := schemaName(t)
	admin, err := sql.Open("pgx", URL())
	if err != nil {
		t.Fatalf("unable to reach the test database: %v", err)
	}
	defer func() { _ = admin.Close() }()

	if _, err := admin.Exec("CREATE SCHEMA " + pq(schema)); err != nil {
		t.Fatalf("unable to create the test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanup, err := sql.Open("pgx", URL())
		if err != nil {
			return
		}
		defer func() { _ = cleanup.Close() }()
		_, _ = cleanup.Exec("DROP SCHEMA " + pq(schema) + " CASCADE")
	})

	// The service creates its own schema here, which is what a local database
	// wants; the deployed one is migrated externally.
	queue, err := lifecycle.OpenConnectionString(
		withSearchPath(URL(), schema), config.MigrationModeManaged)
	if err != nil {
		t.Fatalf("unable to open the lifecycle queue: %v", err)
	}
	t.Cleanup(func() { _ = queue.Close() })
	return queue
}

// EmptySchemaURL creates a schema with nothing in it and returns a connection
// string pointed at it, for the tests that exercise how a store behaves when
// the queue table has not been created yet.
func EmptySchemaURL(t *testing.T) string {
	t.Helper()
	Require(t)

	schema := schemaName(t)
	admin, err := sql.Open("pgx", URL())
	if err != nil {
		t.Fatalf("unable to reach the test database: %v", err)
	}
	defer func() { _ = admin.Close() }()

	if _, err := admin.Exec("CREATE SCHEMA " + pq(schema)); err != nil {
		t.Fatalf("unable to create the test schema: %v", err)
	}
	t.Cleanup(func() {
		cleanup, err := sql.Open("pgx", URL())
		if err != nil {
			return
		}
		defer func() { _ = cleanup.Close() }()
		_, _ = cleanup.Exec("DROP SCHEMA " + pq(schema) + " CASCADE")
	})
	return withSearchPath(URL(), schema)
}

// withSearchPath points a connection at one schema, so the unqualified table
// names in the queue's statements resolve there.
func withSearchPath(base, schema string) string {
	parsed, err := url.Parse(base)
	if err != nil {
		return base
	}
	query := parsed.Query()
	query.Set("search_path", schema)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

// schemaName derives a valid, unique identifier from the test's name.
func schemaName(t *testing.T) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			return r
		case r >= 'A' && r <= 'Z':
			return r + ('a' - 'A')
		default:
			return '_'
		}
	}, t.Name())
	if len(cleaned) > 40 {
		cleaned = cleaned[:40]
	}
	return fmt.Sprintf("t_%s_%d", cleaned, nextSuffix())
}

var (
	suffixMutex sync.Mutex
	suffix      int
)

func nextSuffix() int {
	suffixMutex.Lock()
	defer suffixMutex.Unlock()
	suffix++
	return suffix
}

// pq quotes an identifier this package generated itself.
func pq(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}

// redact keeps a connection string out of a failure message with its password
// still in it.
func redact(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "the configured test database"
	}
	if parsed.User != nil {
		parsed.User = url.User(parsed.User.Username())
	}
	return parsed.String()
}
