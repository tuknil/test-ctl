package config

import (
	"strings"
	"testing"
)

// DATABRICKS_DSN is a convenience for the four connection settings. It carries
// a token, so the rules that matter are: it must never be echoed in an error,
// and an explicit variable must win over it so one field can be changed
// without rewriting the string.

const testDSN = "token:dapi-secret-value@adb-7405605071306757.17.azuredatabricks.net:443" +
	"/sql/1.0/warehouses/866109ed7dfce51a"

func settingsWithDSN(t *testing.T, dsn string, overrides map[string]string) Settings {
	t.Helper()
	t.Setenv("DATABRICKS_DSN", dsn)
	for name, value := range overrides {
		t.Setenv(name, value)
	}
	return Load()
}

func TestDSNSuppliesTheConnectionSettings(t *testing.T) {
	settings := settingsWithDSN(t, testDSN, nil)

	if settings.DatabricksServerHostname != "adb-7405605071306757.17.azuredatabricks.net" {
		t.Errorf("hostname = %q", settings.DatabricksServerHostname)
	}
	if settings.DatabricksHTTPPath != "/sql/1.0/warehouses/866109ed7dfce51a" {
		t.Errorf("http path = %q", settings.DatabricksHTTPPath)
	}
	if settings.DatabricksToken != "dapi-secret-value" {
		t.Errorf("token was not taken from the DSN")
	}
	// A DSN carries a PAT, so it selects PAT auth rather than leaving the
	// default asking for a client id and secret.
	if settings.NormalizedDatabricksAuthType() != "pat" {
		t.Errorf("auth type = %q, want pat", settings.DatabricksAuthType)
	}
	if problems := settings.databricksErrors(); len(problems) > 0 {
		t.Errorf("a complete DSN should satisfy the Databricks settings: %v", problems)
	}
}

func TestDSNAcceptsAnExplicitScheme(t *testing.T) {
	settings := settingsWithDSN(t, "databricks://"+testDSN, nil)

	if settings.DatabricksServerHostname == "" || settings.DatabricksHTTPPath == "" {
		t.Errorf("the scheme-prefixed form should parse: %+v", settings.DatabricksServerHostname)
	}
}

func TestDSNCarriesOptionalCatalogAndSchema(t *testing.T) {
	settings := settingsWithDSN(t, testDSN+"?catalog=other_catalog&schema=other_schema", nil)

	if settings.DatabricksCatalog != "other_catalog" || settings.DatabricksSchema != "other_schema" {
		t.Errorf("catalog/schema = %q/%q",
			settings.DatabricksCatalog, settings.DatabricksSchema)
	}
}

// One field can be changed without rewriting the whole string.
func TestExplicitSettingsOverrideTheDSN(t *testing.T) {
	settings := settingsWithDSN(t, testDSN, map[string]string{
		"DATABRICKS_HTTP_PATH": "/sql/1.0/warehouses/a-different-warehouse",
		"DATABRICKS_CATALOG":   "explicit_catalog",
	})

	if settings.DatabricksHTTPPath != "/sql/1.0/warehouses/a-different-warehouse" {
		t.Errorf("the explicit HTTP path should win: %q", settings.DatabricksHTTPPath)
	}
	if settings.DatabricksCatalog != "explicit_catalog" {
		t.Errorf("the explicit catalog should win: %q", settings.DatabricksCatalog)
	}
	// The rest still comes from the DSN.
	if settings.DatabricksServerHostname == "" {
		t.Error("the DSN should still supply the hostname")
	}
}

// OAuth is not expressible as a DSN, so an explicit auth type is respected and
// the DSN's token is not allowed to switch the deployment to PAT behind it.
func TestExplicitOAuthAuthTypeIsNotOverriddenByADSN(t *testing.T) {
	settings := settingsWithDSN(t, testDSN, map[string]string{
		"DATABRICKS_AUTH_TYPE":     "oauth-m2m",
		"DATABRICKS_CLIENT_ID":     "an-application-id",
		"DATABRICKS_CLIENT_SECRET": "a-secret",
	})

	if settings.NormalizedDatabricksAuthType() != "oauth-m2m" {
		t.Errorf("auth type = %q, want oauth-m2m", settings.DatabricksAuthType)
	}
	if problems := settings.databricksErrors(); len(problems) > 0 {
		t.Errorf("OAuth alongside a DSN should still validate: %v", problems)
	}
}

// The DSN holds a token, so a parse failure must name the problem without
// quoting the value.
func TestMalformedDSNIsReportedWithoutEchoingIt(t *testing.T) {
	cases := map[string]string{
		"no warehouse path": "token:dapi-secret-value@adb-example.azuredatabricks.net:443",
		"no host":           "token:dapi-secret-value@/sql/1.0/warehouses/abc",
		"wrong scheme":      "postgres://token:dapi-secret-value@example.net/sql/1.0/warehouses/abc",
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
				if strings.Contains(problem, "dapi-secret-value") {
					t.Fatalf("a configuration error leaked the token: %s", problem)
				}
			}
			if !reported {
				t.Errorf("the malformed DSN should be reported: %v", problems)
			}
		})
	}
}

func TestNoDSNLeavesTheExplicitSettingsAlone(t *testing.T) {
	settings := settingsWithDSN(t, "", map[string]string{
		"DATABRICKS_SERVER_HOSTNAME": "explicit.databricks.example",
		"DATABRICKS_HTTP_PATH":       "/sql/1.0/warehouses/explicit",
		"DATABRICKS_AUTH_TYPE":       "pat",
		"DATABRICKS_TOKEN":           "explicit-token",
	})

	if settings.DatabricksServerHostname != "explicit.databricks.example" {
		t.Errorf("hostname = %q", settings.DatabricksServerHostname)
	}
	if problems := settings.databricksErrors(); len(problems) > 0 {
		t.Errorf("the explicit form should still validate: %v", problems)
	}
}
