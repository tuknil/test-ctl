package config

import (
	"strings"
	"testing"
)

// The Databricks connection is expressed only as DATABRICKS_DSN: one place a
// workspace is configured, one place a credential lives. The rules that matter
// are that both auth modes are expressible, that an ambiguous credential is
// refused rather than guessed, and that nothing ever echoes the DSN.

const (
	patDSN = "token:dapi-secret-value@adb-7405605071306757.17.azuredatabricks.net:443" +
		"/sql/1.0/warehouses/866109ed7dfce51a"
	oauthDSN = "an-application-id:an-oauth-secret@adb-7405605071306757.17.azuredatabricks.net:443" +
		"/sql/1.0/warehouses/866109ed7dfce51a"
)

func settingsWithDSN(t *testing.T, dsn string, overrides map[string]string) Settings {
	t.Helper()
	t.Setenv("DATABRICKS_DSN", dsn)
	for name, value := range overrides {
		t.Setenv(name, value)
	}
	return Load()
}

func TestTokenDSNSelectsPersonalAccessTokenAuth(t *testing.T) {
	settings := settingsWithDSN(t, patDSN, nil)

	if settings.DatabricksServerHostname != "adb-7405605071306757.17.azuredatabricks.net" {
		t.Errorf("hostname = %q", settings.DatabricksServerHostname)
	}
	if settings.DatabricksHTTPPath != "/sql/1.0/warehouses/866109ed7dfce51a" {
		t.Errorf("http path = %q", settings.DatabricksHTTPPath)
	}
	if settings.NormalizedDatabricksAuthType() != "pat" || settings.DatabricksToken != "dapi-secret-value" {
		t.Errorf("auth = %q token set = %v",
			settings.DatabricksAuthType, settings.DatabricksToken != "")
	}
	if problems := settings.databricksErrors(); len(problems) > 0 {
		t.Errorf("a complete DSN should validate: %v", problems)
	}
}

// OAuth M2M stays expressible, so requiring a DSN does not force every
// deployment onto a personal access token.
func TestServicePrincipalDSNSelectsOAuth(t *testing.T) {
	settings := settingsWithDSN(t, oauthDSN, nil)

	if settings.NormalizedDatabricksAuthType() != "oauth-m2m" {
		t.Fatalf("auth type = %q, want oauth-m2m", settings.DatabricksAuthType)
	}
	if settings.DatabricksClientID != "an-application-id" ||
		settings.DatabricksClientSecret != "an-oauth-secret" {
		t.Errorf("the client credentials were not taken from the DSN")
	}
	if settings.DatabricksToken != "" {
		t.Errorf("a service-principal DSN must not set a token")
	}
	if problems := settings.databricksErrors(); len(problems) > 0 {
		t.Errorf("an OAuth DSN should validate: %v", problems)
	}
}

func TestDSNAcceptsAnExplicitScheme(t *testing.T) {
	settings := settingsWithDSN(t, "databricks://"+patDSN, nil)

	if settings.DatabricksServerHostname == "" || settings.DatabricksHTTPPath == "" {
		t.Error("the scheme-prefixed form should parse")
	}
}

// The DSN is authoritative for what it expresses.
func TestDSNCatalogAndSchemaWin(t *testing.T) {
	settings := settingsWithDSN(t, patDSN+"?catalog=other_catalog&schema=other_schema",
		map[string]string{"DATABRICKS_CATALOG": "ignored"})

	if settings.DatabricksCatalog != "other_catalog" || settings.DatabricksSchema != "other_schema" {
		t.Errorf("catalog/schema = %q/%q",
			settings.DatabricksCatalog, settings.DatabricksSchema)
	}
}

// The individual connection variables are no longer read at all, so a
// deployment still setting them gets a clear failure rather than a service
// that silently ignores half its configuration.
func TestIndividualConnectionVariablesAreNoLongerRead(t *testing.T) {
	settings := settingsWithDSN(t, "", map[string]string{
		"DATABRICKS_SERVER_HOSTNAME": "adb-example.azuredatabricks.net",
		"DATABRICKS_HTTP_PATH":       "/sql/1.0/warehouses/abc",
		"DATABRICKS_AUTH_TYPE":       "pat",
		"DATABRICKS_TOKEN":           "dapi-secret-value",
		"DATABRICKS_CLIENT_ID":       "an-application-id",
		"DATABRICKS_CLIENT_SECRET":   "an-oauth-secret",
	})

	if settings.DatabricksServerHostname != "" || settings.DatabricksToken != "" {
		t.Error("the individual connection variables must not be read")
	}
	problems := settings.databricksErrors()
	if len(problems) != 1 || !strings.Contains(problems[0], "DATABRICKS_DSN is required") {
		t.Errorf("a missing DSN should be the one reported problem: %v", problems)
	}
}

// A bare username could be a PAT written without its prefix or a client id
// missing its secret. Guessing would fail later against the workspace with a
// worse message.
func TestAmbiguousCredentialIsRefused(t *testing.T) {
	settings := settingsWithDSN(t,
		"dapi-secret-value@adb-example.azuredatabricks.net:443/sql/1.0/warehouses/abc", nil)

	problems := settings.databricksErrors()
	if len(problems) == 0 || !strings.Contains(problems[0], "token:<pat>") {
		t.Errorf("an ambiguous credential should say what the forms are: %v", problems)
	}
}

// Every rejection names the problem without quoting the DSN.
func TestMalformedDSNIsReportedWithoutEchoingIt(t *testing.T) {
	cases := map[string]string{
		"no warehouse path": "token:dapi-secret-value@adb-example.azuredatabricks.net:443",
		"no host":           "token:dapi-secret-value@/sql/1.0/warehouses/abc",
		"wrong scheme":      "postgres://token:dapi-secret-value@example.net/sql/1.0/warehouses/abc",
		"no credential":     "adb-example.azuredatabricks.net:443/sql/1.0/warehouses/abc",
		"empty token":       "token:@adb-example.azuredatabricks.net:443/sql/1.0/warehouses/abc",
	}
	for name, dsn := range cases {
		t.Run(name, func(t *testing.T) {
			settings := settingsWithDSN(t, dsn, nil)

			problems := settings.ConfigurationErrors()
			var reported bool
			for _, problem := range problems {
				if strings.Contains(problem, "DATABRICKS_DSN") {
					reported = true
				}
				for _, secret := range []string{"dapi-secret-value", "an-oauth-secret"} {
					if strings.Contains(problem, secret) {
						t.Fatalf("a configuration error leaked a credential: %s", problem)
					}
				}
			}
			if !reported {
				t.Errorf("the malformed DSN should be reported: %v", problems)
			}
		})
	}
}

// The DSN format is shared with the mitigation-check service
// (claude_mitigate/api/databricks.go), which documents it as
// token:<PAT>@<host>[:443]/sql/1.0/warehouses/<id> and normalizes a missing
// port to :443. One operator-written string has to work for both services, so
// both host forms must parse to the same connection here.
func TestDSNHostPortIsOptionalAsInTheMitigationCheckService(t *testing.T) {
	const (
		withPort    = "token:dapi-secret-value@adb-example.azuredatabricks.net:443/sql/1.0/warehouses/abc"
		withoutPort = "token:dapi-secret-value@adb-example.azuredatabricks.net/sql/1.0/warehouses/abc"
	)

	ported := settingsWithDSN(t, withPort, nil)
	bare := settingsWithDSN(t, withoutPort, nil)

	if ported.DatabricksServerHostname != bare.DatabricksServerHostname {
		t.Errorf("hostname differs by port: %q vs %q",
			ported.DatabricksServerHostname, bare.DatabricksServerHostname)
	}
	if ported.DatabricksHTTPPath != bare.DatabricksHTTPPath {
		t.Errorf("http path differs by port: %q vs %q",
			ported.DatabricksHTTPPath, bare.DatabricksHTTPPath)
	}
	if ported.DatabricksToken != bare.DatabricksToken {
		t.Error("the token differs by port")
	}
	for _, settings := range []Settings{ported, bare} {
		if problems := settings.databricksErrors(); len(problems) > 0 {
			t.Errorf("both host forms should validate: %v", problems)
		}
	}
}
