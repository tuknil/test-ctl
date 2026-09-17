package config

import (
	"strings"
	"testing"
)

// The lifecycle queue is configured by one variable. What matters is that a
// deployment cannot start without a usable Postgres URL, and that a URL
// carrying a password never reaches a message about it.

const deployedURL = "postgres://janus:url-password-value@janus.postgres.database.azure.com" +
	":5432/control_translation?sslmode=require"

func settingsFor(t *testing.T, environment map[string]string) Settings {
	t.Helper()
	t.Setenv("DATABRICKS_DSN", patDSN)
	t.Setenv("DATABASE_URL", deployedURL)
	for name, value := range environment {
		t.Setenv(name, value)
	}
	return Load()
}

// databaseProblems returns only the errors about the lifecycle database, so a
// case is not accidentally satisfied by an unrelated complaint.
func databaseProblems(settings Settings) []string {
	var found []string
	for _, problem := range settings.ConfigurationErrors() {
		if strings.Contains(problem, "DATABASE_URL") {
			found = append(found, problem)
		}
	}
	return found
}

func TestTheDeployedConfigurationIsAccepted(t *testing.T) {
	settings := settingsFor(t, nil)

	if problems := databaseProblems(settings); len(problems) != 0 {
		t.Errorf("the deployed configuration was rejected: %v", problems)
	}
	if settings.DatabaseURL != deployedURL {
		t.Errorf("the connection URL was not read: %q", settings.DatabaseURL)
	}
}

func TestTheConnectionURLIsRequired(t *testing.T) {
	problems := databaseProblems(settingsFor(t, map[string]string{"DATABASE_URL": ""}))

	if len(problems) == 0 {
		t.Fatal("a missing DATABASE_URL was accepted")
	}
	// The complaint should show the shape expected, since it is now the only
	// thing to get right.
	if !strings.Contains(problems[0], "postgres://") {
		t.Errorf("the error should show the expected form: %v", problems)
	}
}

// A URL missing the part the connection cannot be made without should fail at
// startup, not on the first query.
func TestAnIncompleteConnectionURLIsRefused(t *testing.T) {
	cases := map[string]string{
		"no host":      "postgres:///control_translation?sslmode=require",
		"no database":  "postgres://janus@host:5432?sslmode=require",
		"wrong scheme": "mysql://janus@host:3306/control_translation",
		"not a url":    "postgres://janus@host:notaport/db",
		"empty":        "   ",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			problems := databaseProblems(settingsFor(t, map[string]string{"DATABASE_URL": raw}))

			if len(problems) == 0 {
				t.Errorf("%q was accepted", raw)
			}
		})
	}
}

// A URL with a user, a password and a database is enough; nothing else is
// demanded of it. sslmode in particular is the operator's choice, so a local
// container over loopback can turn it off.
func TestAUsableURLIsAcceptedWhateverElseItSays(t *testing.T) {
	for _, raw := range []string{
		"postgres://app:secret@127.0.0.1:55432/control_translation?sslmode=disable",
		"postgresql://app@db.internal:5432/control_translation",
		"postgres://app:secret@db:5432/control_translation?sslmode=verify-full&connect_timeout=8",
	} {
		if problems := databaseProblems(
			settingsFor(t, map[string]string{"DATABASE_URL": raw})); len(problems) != 0 {
			t.Errorf("%q was rejected: %v", raw, problems)
		}
	}
}

// Configuration errors are logged and returned. The URL carries the password,
// so it must not be echoed into one.
func TestAMalformedConnectionURLIsNotEchoed(t *testing.T) {
	const secret = "url-password-value"
	environment := map[string]string{
		"DATABASE_URL": "postgres://app:" + secret + "@host:notaport/db",
	}

	for _, problem := range settingsFor(t, environment).ConfigurationErrors() {
		if strings.Contains(problem, secret) {
			t.Errorf("a configuration error echoed the URL password: %s", problem)
		}
	}
}

// Even a URL that parses is never echoed: the deployed one has a password in
// it, and a complaint about some other setting must not carry it along.
func TestAValidConnectionURLIsNeverEchoedEither(t *testing.T) {
	environment := map[string]string{"SERVICE_REPLICA_COUNT": "0"}

	problems := settingsFor(t, environment).ConfigurationErrors()

	if len(problems) == 0 {
		t.Fatal("expected the replica count to be reported")
	}
	for _, problem := range problems {
		if strings.Contains(problem, "url-password-value") {
			t.Errorf("an unrelated error echoed the URL password: %s", problem)
		}
	}
}

// The queue is shared and runs are claimed with FOR UPDATE SKIP LOCKED, so
// more than one replica is a supported deployment. The SQLite queue was a
// local file, which is why that used to be refused.
func TestMoreThanOneReplicaIsAllowed(t *testing.T) {
	environment := map[string]string{"SERVICE_REPLICA_COUNT": "3"}

	for _, problem := range settingsFor(t, environment).ConfigurationErrors() {
		if strings.Contains(problem, "SERVICE_REPLICA_COUNT") {
			t.Errorf("multiple replicas were refused: %s", problem)
		}
	}
}

func TestZeroReplicasIsStillRefused(t *testing.T) {
	environment := map[string]string{"SERVICE_REPLICA_COUNT": "0"}

	if !mentions(settingsFor(t, environment).ConfigurationErrors(), "SERVICE_REPLICA_COUNT") {
		t.Error("a replica count of zero was accepted")
	}
}

// These configured the SQLite file, then the Postgres connection before one
// URL replaced them. A deployment still setting any of them should not appear
// to work while the service reads something else.
func TestTheRetiredDatabaseVariablesAreNoLongerRead(t *testing.T) {
	environment := map[string]string{
		"DATABASE_PATH":           "/app/data/control_translation.db",
		"DATABASE_HOST":           "wrong.example.com",
		"DATABASE_PORT":           "1234",
		"DATABASE_NAME":           "wrong_database",
		"DATABASE_USER":           "wrong-user",
		"DATABASE_PASSWORD":       "wrong-password",
		"DATABASE_SSL_MODE":       "disable",
		"DATABASE_AUTH_MODE":      "entra",
		"DATABASE_MIGRATION_MODE": "external",
		"AZURE_TENANT_ID":         "tenant",
		"AZURE_CLIENT_ID":         "client",
		"AZURE_CLIENT_SECRET":     "secret",
	}

	settings := settingsFor(t, environment)

	if settings.DatabaseURL != deployedURL {
		t.Errorf("a retired variable displaced DATABASE_URL: %q", settings.DatabaseURL)
	}
	if problems := databaseProblems(settings); len(problems) != 0 {
		t.Errorf("a retired variable was still validated: %v", problems)
	}
}

func mentions(problems []string, name string) bool {
	for _, problem := range problems {
		if strings.Contains(problem, name) {
			return true
		}
	}
	return false
}
