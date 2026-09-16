// Package config loads typed settings from the environment.
//
// Variable names and defaults match the Python service, so one environment
// configures either. This lean build reads only what it uses: it has no
// worker, no callbacks, and no SQLite, so those settings are gone.
package config

import (
	"errors"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// Settings is the API service configuration.
type Settings struct {
	RunMode       string // "fixture" | "live"
	ModelProvider string
	ModelName     string

	EnableDocs         bool
	Host               string
	Port               int
	CORSAllowedOrigins []string

	// DatabricksDSN is the single source for the connection. The fields below
	// it are derived from it and are never read from the environment, so there
	// is one place a workspace is configured and one place a credential lives.
	DatabricksDSN string

	DatabricksServerHostname string
	DatabricksHTTPPath       string
	DatabricksAuthType       string
	DatabricksToken          string
	DatabricksClientID       string
	DatabricksClientSecret   string

	// Table coordinates are not connection settings. They stay separate, and
	// the DSN may override catalog and schema for the connection it describes.
	DatabricksCatalog      string
	DatabricksSchema       string
	DatabricksResultsTable string

	// The lifecycle queue is a local SQLite file: durable coordination for
	// this replica only. Completed results go to Databricks.
	DatabasePath               string
	ServiceReplicaCount        int
	WorkerPollSeconds          float64
	WorkerLeaseSeconds         int
	WorkerHeartbeatSeconds     float64
	WorkerMaxAttempts          int
	WorkerShutdownGraceSeconds float64

	DefaultTargetTechnology    string
	DefaultTargetPolicyContext string
}

// Load reads settings from the process environment.
func Load() Settings {
	return applyDSN(load())
}

func load() Settings {
	return Settings{
		RunMode:       strEnv("RUN_MODE", "fixture"),
		ModelProvider: strEnv("MODEL_PROVIDER", "none"),
		ModelName:     strEnv("MODEL_NAME", "not-configured"),

		EnableDocs:         boolEnv("ENABLE_DOCS", true),
		Host:               strEnv("HOST", "0.0.0.0"),
		Port:               intEnv("PORT", 8000),
		CORSAllowedOrigins: listEnv("CORS_ALLOWED_ORIGINS"),

		DatabricksDSN:          os.Getenv("DATABRICKS_DSN"),
		DatabricksCatalog:      strEnv("DATABRICKS_CATALOG", "36889_janus_dev"),
		DatabricksSchema:       strEnv("DATABRICKS_SCHEMA", "control_translation"),
		DatabricksResultsTable: strEnv("DATABRICKS_RESULTS_TABLE", "control_translation_results"),

		DatabasePath:               strEnv("DATABASE_PATH", "/app/data/control_translation.db"),
		ServiceReplicaCount:        intEnv("SERVICE_REPLICA_COUNT", 1),
		WorkerPollSeconds:          floatEnv("WORKER_POLL_SECONDS", 0.25),
		WorkerLeaseSeconds:         intEnv("WORKER_LEASE_SECONDS", 30),
		WorkerHeartbeatSeconds:     floatEnv("WORKER_HEARTBEAT_SECONDS", 5),
		WorkerMaxAttempts:          intEnv("WORKER_MAX_ATTEMPTS", 3),
		WorkerShutdownGraceSeconds: floatEnv("WORKER_SHUTDOWN_GRACE_SECONDS", 2),

		DefaultTargetTechnology:    strEnv("DEFAULT_TARGET_TECHNOLOGY", "akamai-waf"),
		DefaultTargetPolicyContext: strEnv("DEFAULT_TARGET_POLICY_CONTEXT_ID", "akamai-policy:example:rev-17"),
	}
}

// applyDSN derives the connection settings from DATABRICKS_DSN. A malformed
// DSN leaves them empty so ConfigurationErrors can report it; the DSN is never
// echoed, because it carries a credential.
func applyDSN(settings Settings) Settings {
	parsed, err := parseDatabricksDSN(settings.DatabricksDSN)
	if err != nil || parsed == nil {
		return settings
	}
	settings.DatabricksServerHostname = parsed.hostname
	settings.DatabricksHTTPPath = parsed.httpPath
	settings.DatabricksAuthType = parsed.authType
	settings.DatabricksToken = parsed.token
	settings.DatabricksClientID = parsed.clientID
	settings.DatabricksClientSecret = parsed.clientSecret
	// The DSN is authoritative for anything it expresses, including the
	// catalog and schema of the connection it describes.
	if parsed.catalog != "" {
		settings.DatabricksCatalog = parsed.catalog
	}
	if parsed.schema != "" {
		settings.DatabricksSchema = parsed.schema
	}
	return settings
}

type databricksDSN struct {
	hostname     string
	httpPath     string
	authType     string
	token        string
	clientID     string
	clientSecret string
	catalog      string
	schema       string
}

// parseDatabricksDSN accepts the databricks-sql-go connection string:
//
//	token:<pat>@<host>:443/sql/1.0/warehouses/<id>?catalog=c&schema=s
//
// The userinfo selects the authentication mode. A literal "token" username
// means a personal access token; anything else is an OAuth M2M service
// principal, where the username is the client id and the password its secret:
//
//	<client-id>:<client-secret>@<host>:443/sql/1.0/warehouses/<id>
//
// The databricks:// scheme is optional. It returns (nil, nil) when no DSN was
// supplied. Errors never quote the DSN, which holds a credential.
func parseDatabricksDSN(dsn string) (*databricksDSN, error) {
	dsn = strings.TrimSpace(dsn)
	if dsn == "" {
		return nil, nil
	}
	if !strings.Contains(dsn, "://") {
		dsn = "databricks://" + dsn
	}
	parsed, err := url.Parse(dsn)
	if err != nil {
		return nil, errors.New("DATABRICKS_DSN is not a valid connection string")
	}
	if parsed.Scheme != "databricks" {
		return nil, errors.New("DATABRICKS_DSN scheme must be databricks")
	}
	if parsed.Hostname() == "" {
		return nil, errors.New("DATABRICKS_DSN must include a host")
	}
	result := &databricksDSN{
		hostname: parsed.Hostname(),
		httpPath: parsed.EscapedPath(),
		catalog:  parsed.Query().Get("catalog"),
		schema:   parsed.Query().Get("schema"),
	}
	if parsed.User == nil {
		return nil, errors.New("DATABRICKS_DSN must carry a credential")
	}
	username := parsed.User.Username()
	password, hasPassword := parsed.User.Password()
	switch {
	case username == "token":
		if !hasPassword || password == "" {
			return nil, errors.New("DATABRICKS_DSN token form needs token:<pat>@host")
		}
		result.authType, result.token = "pat", password
	case hasPassword && password != "":
		result.authType = "oauth-m2m"
		result.clientID, result.clientSecret = username, password
	default:
		// A bare username is ambiguous: it could be a PAT written without the
		// token: prefix, or a client id missing its secret. Refuse rather than
		// pick one and fail later against the workspace.
		return nil, errors.New(
			"DATABRICKS_DSN credential must be token:<pat> or <client-id>:<client-secret>")
	}
	if result.httpPath == "" || result.httpPath == "/" {
		return nil, errors.New("DATABRICKS_DSN must include the warehouse HTTP path")
	}
	return result, nil
}

// IsLive reports whether the deployment claims live mode. This service has no
// model client, so live mode changes only how the runtime reports itself.
func (s Settings) IsLive() bool { return strings.EqualFold(strings.TrimSpace(s.RunMode), "live") }

// NormalizedDatabricksAuthType is the lowercased Databricks auth type.
func (s Settings) NormalizedDatabricksAuthType() string {
	return strings.ToLower(strings.TrimSpace(s.DatabricksAuthType))
}

// CredentialsConfigured is always false: no model provider is compiled in, so
// the runtime never claims to hold model credentials.
func (s Settings) CredentialsConfigured() bool { return false }

// ConfigurationErrors returns safe configuration errors, never secret values.
func (s Settings) ConfigurationErrors() []string {
	var errs []string
	mode := strings.ToLower(strings.TrimSpace(s.RunMode))
	if mode != "fixture" && mode != "live" {
		errs = append(errs, "RUN_MODE must be either 'fixture' or 'live'.")
	}
	if mode == "live" {
		// Refusing to start in live mode is deliberate: this build compiles
		// rules deterministically and has no model client, so a live
		// deployment would silently serve non-model output.
		errs = append(errs, "RUN_MODE=live is not supported by this build; it has no model client.")
	}
	if s.Port < 1 || s.Port > 65535 {
		errs = append(errs, "PORT must be between 1 and 65535.")
	}
	errs = append(errs, corsErrors(s.CORSAllowedOrigins)...)
	errs = append(errs, s.workerErrors()...)
	errs = append(errs, s.databricksErrors()...)
	return errs
}

// workerErrors validates the lifecycle worker. The replica constraint is not
// cosmetic: the queue is a local SQLite file, so a second replica would have
// its own queue and its own view of which runs are claimed.
func (s Settings) workerErrors() []string {
	var errs []string
	if s.ServiceReplicaCount != 1 {
		errs = append(errs,
			"SERVICE_REPLICA_COUNT must be 1 while the lifecycle queue is a local SQLite file.")
	}
	if s.WorkerPollSeconds <= 0 {
		errs = append(errs, "WORKER_POLL_SECONDS must be greater than zero.")
	}
	if s.WorkerLeaseSeconds < 2 {
		errs = append(errs, "WORKER_LEASE_SECONDS must be at least 2.")
	}
	if s.WorkerHeartbeatSeconds <= 0 || s.WorkerHeartbeatSeconds >= float64(s.WorkerLeaseSeconds) {
		errs = append(errs,
			"WORKER_HEARTBEAT_SECONDS must be positive and shorter than the lease.")
	}
	if s.WorkerMaxAttempts < 1 {
		errs = append(errs, "WORKER_MAX_ATTEMPTS must be at least 1.")
	}
	if s.WorkerShutdownGraceSeconds <= 0 {
		errs = append(errs, "WORKER_SHUTDOWN_GRACE_SECONDS must be greater than zero.")
	}
	if strings.TrimSpace(s.DatabasePath) == "" {
		errs = append(errs, "DATABASE_PATH is required for durable lifecycle coordination.")
	}
	return errs
}

// databricksErrors validates the only persistence backend this build has.
//
// The connection comes from DATABRICKS_DSN alone, so a missing or malformed
// DSN is the single thing to report; the derived fields cannot be wrong
// independently of it.
func (s Settings) databricksErrors() []string {
	var errs []string
	if strings.TrimSpace(s.DatabricksDSN) == "" {
		errs = append(errs,
			"DATABRICKS_DSN is required: token:<pat>@<host>:443/sql/1.0/warehouses/<id> "+
				"for a personal access token, or <client-id>:<client-secret>@... for an "+
				"OAuth M2M service principal.")
		return errs
	}
	if _, err := parseDatabricksDSN(s.DatabricksDSN); err != nil {
		// Named, never echoed: the DSN carries a credential.
		return append(errs, err.Error()+".")
	}
	missing := []string{}
	for _, name := range []string{
		"DATABRICKS_CATALOG", "DATABRICKS_RESULTS_TABLE", "DATABRICKS_SCHEMA",
	} {
		value := map[string]string{
			"DATABRICKS_CATALOG":       s.DatabricksCatalog,
			"DATABRICKS_SCHEMA":        s.DatabricksSchema,
			"DATABRICKS_RESULTS_TABLE": s.DatabricksResultsTable,
		}[name]
		if strings.TrimSpace(value) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		errs = append(errs, "Databricks persistence is missing required settings: "+
			strings.Join(missing, ", ")+".")
	}
	return errs
}

func corsErrors(origins []string) []string {
	var errs []string
	for _, origin := range origins {
		if origin == "*" {
			errs = append(errs, "CORS_ALLOWED_ORIGINS must name explicit origins, not '*'.")
			continue
		}
		parsed, err := url.Parse(origin)
		switch {
		case err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "":
			errs = append(errs, fmt.Sprintf(
				"CORS_ALLOWED_ORIGINS entry '%s' must be a full http or https origin.", origin))
		case parsed.Path != "":
			errs = append(errs, fmt.Sprintf(
				"CORS_ALLOWED_ORIGINS entry '%s' must not include a path.", origin))
		}
	}
	return errs
}

// Ready reports whether the service may enter rotation.
func (s Settings) Ready() bool { return len(s.ConfigurationErrors()) == 0 }

func strEnv(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func intEnv(name string, fallback int) int {
	if value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name))); err == nil {
		return value
	}
	return fallback
}

func floatEnv(name string, fallback float64) float64 {
	if value, err := strconv.ParseFloat(strings.TrimSpace(os.Getenv(name)), 64); err == nil {
		return value
	}
	return fallback
}

func boolEnv(name string, fallback bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "":
		return fallback
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func listEnv(name string) []string {
	raw := os.Getenv(name)
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var items []string
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimRight(strings.TrimSpace(part), "/"); trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return items
}
