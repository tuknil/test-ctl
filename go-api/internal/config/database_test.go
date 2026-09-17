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
		"DATABASE_AUTH_MODE":         "entra",
		"DATABASE_HOST":              "janus.postgres.database.azure.com",
		"DATABASE_PORT":              "5432",
		"DATABASE_NAME":              "control_translation",
		"DATABASE_USER":              "janus-app",
		"DATABASE_SSL_MODE":          "verify-full",
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

// The connection carries a bearer token. A mode that can silently fall back to
// plaintext would put that token on the wire in the clear.
func TestSSLModesThatAllowAPlaintextFallbackAreRefused(t *testing.T) {
	for _, mode := range []string{"disable", "allow", "prefer"} {
		t.Run("mode="+mode, func(t *testing.T) {
			environment := azureEnvironment()
			environment["DATABASE_SSL_MODE"] = mode

			problems := databaseProblems(settingsFor(t, environment))

			if !mentions(problems, "DATABASE_SSL_MODE") {
				t.Errorf("%q was accepted: %v", mode, problems)
			}
		})
	}
}

// An unset DATABASE_SSL_MODE must not mean "no TLS". The default is the
// strictest mode, so a deployment that forgets it still verifies the server.
func TestTheDefaultSSLModeVerifiesTheServer(t *testing.T) {
	environment := azureEnvironment()
	delete(environment, "DATABASE_SSL_MODE")

	settings := settingsFor(t, environment)

	if settings.DatabaseSSLMode != "verify-full" {
		t.Errorf("default sslmode = %q, want verify-full", settings.DatabaseSSLMode)
	}
}

func TestVerifyingSSLModesAreAccepted(t *testing.T) {
	for _, mode := range []string{"require", "verify-ca", "verify-full"} {
		environment := azureEnvironment()
		environment["DATABASE_SSL_MODE"] = mode

		if problems := databaseProblems(settingsFor(t, environment)); len(problems) != 0 {
			t.Errorf("%q was rejected: %v", mode, problems)
		}
	}
}

func TestTheDatabaseCoordinatesAreRequired(t *testing.T) {
	for _, missing := range []string{"DATABASE_HOST", "DATABASE_NAME", "DATABASE_USER"} {
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

// The password path is for local and non-Azure databases, where the Entra
// principal is meaningless and the secret is the credential.
func TestPasswordModeRequiresAPasswordAndNotAPrincipal(t *testing.T) {
	environment := azureEnvironment()
	environment["DATABASE_AUTH_MODE"] = "password"
	environment["AZURE_TENANT_ID"] = ""
	environment["AZURE_CLIENT_ID"] = ""
	environment["AZURE_CLIENT_SECRET"] = ""

	problems := databaseProblems(settingsFor(t, environment))
	if !mentions(problems, "DATABASE_PASSWORD") {
		t.Errorf("password mode without a password was accepted: %v", problems)
	}

	environment["DATABASE_PASSWORD"] = "local-secret"
	if problems := databaseProblems(settingsFor(t, environment)); len(problems) != 0 {
		t.Errorf("password mode with a password was rejected: %v", problems)
	}
}

// Configuration errors are logged and returned. A secret in one would be
// copied wherever those go.
func TestConfigurationErrorsNeverEchoTheSecret(t *testing.T) {
	const secret = "super-secret-value"
	environment := azureEnvironment()
	environment["DATABASE_HOST"] = ""
	environment["DATABASE_SSL_MODE"] = "disable"

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

// DATABASE_PATH configured the SQLite file. A deployment still setting it
// should not appear to work while the service reads something else.
func TestTheRetiredSQLitePathIsNoLongerRead(t *testing.T) {
	environment := azureEnvironment()
	environment["DATABASE_PATH"] = "/app/data/control_translation.db"

	settings := settingsFor(t, environment)

	if settings.DatabaseHost != "janus.postgres.database.azure.com" {
		t.Errorf("DATABASE_PATH displaced the Postgres coordinates: %+v", settings)
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
