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

	// DatabricksDSN is a single connection string in the databricks-sql-go
	// format. It fills in hostname, HTTP path, token and optionally
	// catalog/schema; explicit DATABRICKS_* variables override whatever it
	// supplies, so one field can be changed without rewriting the string.
	DatabricksDSN            string
	DatabricksServerHostname string
	DatabricksHTTPPath       string
	DatabricksAuthType       string
	DatabricksToken          string
	DatabricksClientID       string
	DatabricksClientSecret   string
	DatabricksCatalog        string
	DatabricksSchema         string
	DatabricksResultsTable   string

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

		DatabricksDSN:            os.Getenv("DATABRICKS_DSN"),
		DatabricksServerHostname: os.Getenv("DATABRICKS_SERVER_HOSTNAME"),
		DatabricksHTTPPath:       os.Getenv("DATABRICKS_HTTP_PATH"),
		DatabricksAuthType:       strEnv("DATABRICKS_AUTH_TYPE", "oauth-m2m"),
		DatabricksToken:          os.Getenv("DATABRICKS_TOKEN"),
		DatabricksClientID:       os.Getenv("DATABRICKS_CLIENT_ID"),
		DatabricksClientSecret:   os.Getenv("DATABRICKS_CLIENT_SECRET"),
		DatabricksCatalog:        strEnv("DATABRICKS_CATALOG", "36889_janus_dev"),
		DatabricksSchema:         strEnv("DATABRICKS_SCHEMA", "control_translation"),
		DatabricksResultsTable:   strEnv("DATABRICKS_RESULTS_TABLE", "control_translation_results"),

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

// applyDSN expands DATABRICKS_DSN into the individual settings, leaving any
// that were set explicitly alone. A malformed DSN is left in place so
// ConfigurationErrors can report it; it is never echoed, because it carries a
// token.
func applyDSN(settings Settings) Settings {
	parsed, err := parseDatabricksDSN(settings.DatabricksDSN)
	if err != nil || parsed == nil {
		return settings
	}
	if settings.DatabricksServerHostname == "" {
		settings.DatabricksServerHostname = parsed.hostname
	}
	if settings.DatabricksHTTPPath == "" {
		settings.DatabricksHTTPPath = parsed.httpPath
	}
	if settings.DatabricksToken == "" && parsed.token != "" {
		settings.DatabricksToken = parsed.token
		// A DSN carries a personal access token, so it selects PAT auth unless
		// the deployment said otherwise explicitly.
		if os.Getenv("DATABRICKS_AUTH_TYPE") == "" {
			settings.DatabricksAuthType = "pat"
		}
	}
	if parsed.catalog != "" && os.Getenv("DATABRICKS_CATALOG") == "" {
		settings.DatabricksCatalog = parsed.catalog
	}
	if parsed.schema != "" && os.Getenv("DATABRICKS_SCHEMA") == "" {
		settings.DatabricksSchema = parsed.schema
	}
	return settings
}

type databricksDSN struct {
	hostname string
	httpPath string
	token    string
	catalog  string
	schema   string
}

// parseDatabricksDSN accepts the databricks-sql-go connection string:
//
//	token:<pat>@<host>:443/sql/1.0/warehouses/<id>?catalog=c&schema=s
//
// with an optional databricks:// scheme. It returns (nil, nil) when no DSN was
// supplied. Errors never quote the DSN, which holds the token.
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
	if parsed.User != nil {
		// The canonical form is token:<pat>@host; a bare user is taken as the
		// token so a hand-written DSN still works.
		if password, ok := parsed.User.Password(); ok {
			result.token = password
		} else {
			result.token = parsed.User.Username()
		}
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
	if _, err := parseDatabricksDSN(s.DatabricksDSN); err != nil {
		// The message names the problem without echoing the DSN, which holds
		// a token.
		errs = append(errs, err.Error()+".")
	}
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
func (s Settings) databricksErrors() []string {
	required := map[string]string{
		"DATABRICKS_SERVER_HOSTNAME": s.DatabricksServerHostname,
		"DATABRICKS_HTTP_PATH":       s.DatabricksHTTPPath,
		"DATABRICKS_CATALOG":         s.DatabricksCatalog,
		"DATABRICKS_SCHEMA":          s.DatabricksSchema,
		"DATABRICKS_RESULTS_TABLE":   s.DatabricksResultsTable,
	}
	var errs []string
	switch s.NormalizedDatabricksAuthType() {
	case "pat":
		required["DATABRICKS_TOKEN"] = s.DatabricksToken
	case "oauth-m2m":
		required["DATABRICKS_CLIENT_ID"] = s.DatabricksClientID
		required["DATABRICKS_CLIENT_SECRET"] = s.DatabricksClientSecret
	default:
		errs = append(errs, "DATABRICKS_AUTH_TYPE must be either 'oauth-m2m' or 'pat'.")
	}
	var missing []string
	for _, name := range sortedKeys(required) {
		if strings.TrimSpace(required[name]) == "" {
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

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}
