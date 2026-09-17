package config

import (
	"strings"
	"testing"
)

// The lifecycle queue is Azure Database for PostgreSQL, authenticated with an
// Entra token. What matters here is that a deployment cannot start
// half-configured -- an Entra mode with no principal, or a TLS mode that
// permits a plaintext fallback -- and that the secret never reaches a message.

// azureEnvironment is the deployed configuration, as the service is given it.
func azureEnvironment() map[string]string {
	return map[string]string{
		"DATABASE_URL": "postgres://janus-app@janus.postgres.database.azure.com:5432" +
			"/control_translation?sslmode=verify-full",
		"DATABASE_AUTH_MODE":         "entra",
		"DATABASE_MIGRATION_MODE":    "external",
		"AZURE_TENANT_ID":            "tenant-1",
		"AZURE_CLIENT_ID":            "client-1",
		"AZURE_CLIENT_SECRET":        "super-secret-value",
		"AZURE_POSTGRES_TOKEN_SCOPE": "https://ossrdbms-aad.database.windows.net/.default",
	}
}

func settingsFor(t *testing.T, environment map[string]string) Settings {
	t.Helper()
	t.Setenv("DATABRICKS_DSN", patDSN)
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
		if strings.Contains(problem, "DATABASE_") || strings.Contains(problem, "AZURE_") {
			found = append(found, problem)
		}
	}
	return found
}

func TestTheDeployedAzureConfigurationIsAccepted(t *testing.T) {
	settings := settingsFor(t, azureEnvironment())

	if problems := databaseProblems(settings); len(problems) != 0 {
		t.Errorf("the deployed configuration was rejected: %v", problems)
	}
	if settings.DatabaseAuthMode != AuthModeEntra ||
		settings.DatabaseMigrationMode != MigrationModeExternal {
		t.Errorf("unexpected modes: %+v", settings)
	}
	if !strings.Contains(settings.DatabaseURL, "janus.postgres.database.azure.com") {
		t.Errorf("the connection URL was not read: %q", settings.DatabaseURL)
	}
}

// The Entra path has no password, so the principal is the credential. Starting
// without it would fail on the first connection instead of at startup.
func TestEntraModeRequiresItsPrincipal(t *testing.T) {
	for _, missing := range []string{
		"AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET",
	} {
		t.Run(missing, func(t *testing.T) {
			environment := azureEnvironment()
			environment[missing] = ""

			problems := databaseProblems(settingsFor(t, environment))

			if !mentions(problems, missing) {
				t.Errorf("a missing %s was not reported: %v", missing, problems)
			}
		})
	}
}

// The Entra connection carries a bearer token. A mode that can silently fall
// back to plaintext would put that token on the wire in the clear.
func TestEntraRefusesSSLModesThatAllowAPlaintextFallback(t *testing.T) {
	for _, mode := range []string{"disable", "allow", "prefer"} {
		t.Run("mode="+mode, func(t *testing.T) {
			environment := azureEnvironment()
			environment["DATABASE_URL"] = "postgres://janus-app@host:5432/db?sslmode=" + mode

			problems := databaseProblems(settingsFor(t, environment))

			if !mentions(problems, "sslmode") {
				t.Errorf("%q was accepted on the entra path: %v", mode, problems)
			}
		})
	}
}

// An Entra URL with no sslmode at all is refused too: libpq's own default is
// "prefer", which is exactly the silent fallback being guarded against.
func TestEntraRefusesAURLWithNoSSLModeAtAll(t *testing.T) {
	environment := azureEnvironment()
	environment["DATABASE_URL"] = "postgres://janus-app@host:5432/db"

	if !mentions(databaseProblems(settingsFor(t, environment)), "sslmode") {
		t.Error("an entra URL with no sslmode was accepted")
	}
}

// The password path is local and non-Azure, where there is no token to
// protect, so a loopback connection may use sslmode=disable.
func TestThePasswordPathAllowsAPlaintextLocalConnection(t *testing.T) {
	environment := azureEnvironment()
	environment["DATABASE_AUTH_MODE"] = "password"
	environment["DATABASE_URL"] = "postgres://app:secret@127.0.0.1:55432/db?sslmode=disable"

	if problems := databaseProblems(settingsFor(t, environment)); len(problems) != 0 {
		t.Errorf("a local password connection was rejected: %v", problems)
	}
}

func TestVerifyingSSLModesAreAccepted(t *testing.T) {
	for _, mode := range []string{"require", "verify-ca", "verify-full"} {
		environment := azureEnvironment()
		environment["DATABASE_URL"] = "postgres://janus-app@host:5432/db?sslmode=" + mode

		if problems := databaseProblems(settingsFor(t, environment)); len(problems) != 0 {
			t.Errorf("%q was rejected: %v", mode, problems)
		}
	}
}

func TestTheConnectionURLIsRequired(t *testing.T) {
	environment := azureEnvironment()
	environment["DATABASE_URL"] = ""

	problems := databaseProblems(settingsFor(t, environment))

	if !mentions(problems, "DATABASE_URL") {
		t.Errorf("a missing DATABASE_URL was not reported: %v", problems)
	}
}

// A URL that is missing the part the connection cannot be made without should
// fail at startup, not on the first query.
func TestAnIncompleteConnectionURLIsRefused(t *testing.T) {
	cases := map[string]string{
		"no host":     "postgres:///control_translation?sslmode=verify-full",
		"no database": "postgres://janus-app@host:5432?sslmode=verify-full",
		"wrong scheme": "mysql://janus-app@host:3306/control_translation" +
			"?sslmode=verify-full",
		"not a url": "postgres://janus-app@host:notaport/db",
		// The Entra token is minted for a principal, so the URL has to say who.
		"no user on the entra path": "postgres://host:5432/control_translation" +
			"?sslmode=verify-full",
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			environment := azureEnvironment()
			environment["DATABASE_URL"] = raw

			if problems := databaseProblems(settingsFor(t, environment)); len(problems) == 0 {
				t.Errorf("%q was accepted", raw)
			}
		})
	}
}

// A malformed URL may still contain a password, so the value must not be
// echoed back in the complaint about it.
func TestAMalformedConnectionURLIsNotEchoed(t *testing.T) {
	const secret = "url-password-value"
	environment := azureEnvironment()
	environment["DATABASE_URL"] = "postgres://app:" + secret + "@host:notaport/db"

	for _, problem := range settingsFor(t, environment).ConfigurationErrors() {
		if strings.Contains(problem, secret) {
			t.Errorf("a configuration error echoed the URL password: %s", problem)
		}
	}
}

func TestAnUnknownAuthModeIsRefusedRatherThanAssumed(t *testing.T) {
	environment := azureEnvironment()
	environment["DATABASE_AUTH_MODE"] = "managed-identity"

	problems := databaseProblems(settingsFor(t, environment))

	if !mentions(problems, "DATABASE_AUTH_MODE") {
		t.Errorf("an unimplemented auth mode was accepted: %v", problems)
	}
}

func TestAnUnknownMigrationModeIsRefused(t *testing.T) {
	environment := azureEnvironment()
	environment["DATABASE_MIGRATION_MODE"] = "auto"

	problems := databaseProblems(settingsFor(t, environment))

	if !mentions(problems, "DATABASE_MIGRATION_MODE") {
		t.Errorf("an unknown migration mode was accepted: %v", problems)
	}
}

// The Entra principal is meaningless on the password path, where the
// credential is in the URL, so it is not demanded there.
func TestPasswordModeDoesNotRequireAnEntraPrincipal(t *testing.T) {
	environment := azureEnvironment()
	environment["DATABASE_AUTH_MODE"] = "password"
	environment["DATABASE_URL"] = "postgres://app:secret@127.0.0.1:5432/db?sslmode=require"
	environment["AZURE_TENANT_ID"] = ""
	environment["AZURE_CLIENT_ID"] = ""
	environment["AZURE_CLIENT_SECRET"] = ""

	if problems := databaseProblems(settingsFor(t, environment)); len(problems) != 0 {
		t.Errorf("password mode was made to supply an Entra principal: %v", problems)
	}
}

// Configuration errors are logged and returned. A secret in one would be
// copied wherever those go.
func TestConfigurationErrorsNeverEchoTheSecret(t *testing.T) {
	const secret = "super-secret-value"
	environment := azureEnvironment()
	environment["DATABASE_URL"] = "postgres://janus-app@host:5432/db?sslmode=disable"

	for _, problem := range settingsFor(t, environment).ConfigurationErrors() {
		if strings.Contains(problem, secret) {
			t.Errorf("a configuration error echoed the client secret: %s", problem)
		}
	}
}

// The SQLite queue was a local file, so a second replica meant a second queue.
// Postgres is shared and claims are made with FOR UPDATE SKIP LOCKED, so more
// than one replica is now a supported deployment rather than a misconfiguration.
func TestMoreThanOneReplicaIsAllowed(t *testing.T) {
	environment := azureEnvironment()
	environment["SERVICE_REPLICA_COUNT"] = "3"

	for _, problem := range settingsFor(t, environment).ConfigurationErrors() {
		if strings.Contains(problem, "SERVICE_REPLICA_COUNT") {
			t.Errorf("multiple replicas were refused: %s", problem)
		}
	}
}

func TestZeroReplicasIsStillRefused(t *testing.T) {
	environment := azureEnvironment()
	environment["SERVICE_REPLICA_COUNT"] = "0"

	if !mentionsAny(settingsFor(t, environment).ConfigurationErrors(), "SERVICE_REPLICA_COUNT") {
		t.Error("a replica count of zero was accepted")
	}
}

// DATABASE_PATH configured the SQLite file, and DATABASE_HOST and its
// neighbours configured Postgres before the URL replaced them. A deployment
// still setting any of them should not appear to work while the service reads
// something else.
func TestTheRetiredDatabaseVariablesAreNoLongerRead(t *testing.T) {
	environment := azureEnvironment()
	environment["DATABASE_PATH"] = "/app/data/control_translation.db"
	environment["DATABASE_HOST"] = "wrong.example.com"
	environment["DATABASE_PORT"] = "1234"
	environment["DATABASE_NAME"] = "wrong_database"
	environment["DATABASE_USER"] = "wrong-user"
	environment["DATABASE_PASSWORD"] = "wrong-password"
	environment["DATABASE_SSL_MODE"] = "disable"

	settings := settingsFor(t, environment)

	if !strings.Contains(settings.DatabaseURL, "janus.postgres.database.azure.com") {
		t.Errorf("a retired variable displaced DATABASE_URL: %q", settings.DatabaseURL)
	}
	if problems := databaseProblems(settings); len(problems) != 0 {
		t.Errorf("a retired variable was still validated: %v", problems)
	}
}

func mentions(problems []string, name string) bool { return mentionsAny(problems, name) }

func mentionsAny(problems []string, name string) bool {
	for _, problem := range problems {
		if strings.Contains(problem, name) {
			return true
		}
	}
	return false
}
