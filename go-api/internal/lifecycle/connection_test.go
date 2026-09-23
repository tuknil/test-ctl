package lifecycle

import (
	"net/url"
	"testing"
)

// DATABASE_URL is the whole connection and the only setting for it, so the one
// thing this has to get right is leaving it alone.

func TestTheConnectionStringIsTheConfiguredURL(t *testing.T) {
	const configured = "postgres://janus:secret@db.example.com:5432/control_translation?sslmode=require"

	parsed, err := url.Parse(connectionString(configured))
	if err != nil {
		t.Fatalf("the connection string is not a URL: %v", err)
	}

	if parsed.Host != "db.example.com:5432" {
		t.Errorf("host = %s", parsed.Host)
	}
	if parsed.Path != "/control_translation" {
		t.Errorf("database = %s", parsed.Path)
	}
	if parsed.User.Username() != "janus" {
		t.Errorf("user = %s", parsed.User.Username())
	}
	password, set := parsed.User.Password()
	if !set || password != "secret" {
		t.Error("the credential in the URL was not preserved")
	}
	if got := parsed.Query().Get("sslmode"); got != "require" {
		t.Errorf("sslmode = %q, want the mode the URL set", got)
	}
	// The one addition: a session holding a queue lock should be identifiable
	// in pg_stat_activity.
	if got := parsed.Query().Get("application_name"); got != "control-translation-go" {
		t.Errorf("application_name = %q", got)
	}
}

// Whatever the URL already carries is the operator's, including the choices
// this code would otherwise make for them.
func TestTheConnectionStringPreservesTheURLsOwnParameters(t *testing.T) {
	const configured = "postgres://janus@host:5432/db" +
		"?sslmode=verify-full&connect_timeout=8&application_name=set-by-operator"

	parsed, err := url.Parse(connectionString(configured))
	if err != nil {
		t.Fatalf("the connection string is not a URL: %v", err)
	}
	query := parsed.Query()

	if query.Get("connect_timeout") != "8" {
		t.Errorf("an unrelated parameter was dropped: %v", query)
	}
	if query.Get("sslmode") != "verify-full" {
		t.Errorf("sslmode was rewritten to %q", query.Get("sslmode"))
	}
	if query.Get("application_name") != "set-by-operator" {
		t.Errorf("application_name was overwritten: %q", query.Get("application_name"))
	}
}

// A URL this cannot parse is passed through rather than half-rebuilt, so the
// driver reports it instead of this returning something that is not the
// operator's string.
func TestAnUnparsableURLIsPassedThroughUnchanged(t *testing.T) {
	const broken = "postgres://user:pass@host:notaport/db"

	if got := connectionString(broken); got != broken {
		t.Errorf("connectionString(%q) = %q", broken, got)
	}
}

func TestSurroundingWhitespaceIsTrimmed(t *testing.T) {
	parsed, err := url.Parse(connectionString("  postgres://janus@host:5432/db  "))
	if err != nil {
		t.Fatalf("whitespace was not trimmed: %v", err)
	}
	if parsed.Host != "host:5432" {
		t.Errorf("host = %s", parsed.Host)
	}
}
