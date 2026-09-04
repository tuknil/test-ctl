// Package databricks talks to Unity Catalog through the SQL Statement
// Execution REST API.
//
// The REST API is used rather than a JDBC/Thrift driver so the service stays
// a static binary with no native dependencies. Both the upstream reader and
// the result store share this one client, so authentication, error handling,
// and parameter binding are implemented once.
package databricks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ATT-CSO/control-translation/go-api/internal/config"
)

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// Parameter is one named statement parameter. Values are always sent out of
// band; no caller input is ever concatenated into SQL text.
type Parameter struct {
	Name  string
	Value string
	Kind  string
}

// String builds a STRING parameter.
func String(name, value string) Parameter {
	return Parameter{Name: name, Value: value, Kind: "STRING"}
}

// Int builds an INT parameter.
func Int(name string, value int) Parameter {
	return Parameter{Name: name, Value: strconv.Itoa(value), Kind: "INT"}
}

// Timestamp builds a TIMESTAMP parameter from an already-formatted value.
func Timestamp(name, value string) Parameter {
	return Parameter{Name: name, Value: value, Kind: "TIMESTAMP"}
}

// Client executes statements against one warehouse.
type Client struct {
	settings config.Settings
	http     *http.Client
	// baseOverride replaces the workspace origin in tests only.
	baseOverride string

	tokenMu     sync.Mutex
	token       string
	tokenExpiry time.Time
}

// New builds a client for the configured workspace.
func New(settings config.Settings) *Client {
	return &Client{settings: settings, http: &http.Client{Timeout: 60 * time.Second}}
}

// NewWithBaseURL is New against an explicit workspace origin, for tests.
func NewWithBaseURL(settings config.Settings, baseURL string) *Client {
	client := New(settings)
	client.baseOverride = baseURL
	return client
}

// BaseURL is the workspace origin. Production always derives it from
// DATABRICKS_SERVER_HOSTNAME over TLS.
func (c *Client) BaseURL() string {
	if c.baseOverride != "" {
		return c.baseOverride
	}
	return "https://" + c.settings.DatabricksServerHostname
}

type statementResponse struct {
	Status struct {
		State string `json:"state"`
		Error *struct {
			ErrorCode string `json:"error_code"`
			Message   string `json:"message"`
		} `json:"error"`
	} `json:"status"`
	Result *struct {
		DataArray [][]*string `json:"data_array"`
	} `json:"result"`
}

// Query executes one statement and returns its rows.
func (c *Client) Query(statement string, parameters ...Parameter) ([][]*string, error) {
	token, err := c.accessToken()
	if err != nil {
		return nil, err
	}
	encoded := make([]map[string]any, 0, len(parameters))
	for _, item := range parameters {
		entry := map[string]any{"name": item.Name, "type": item.Kind}
		// An empty string for a nullable column is sent as SQL NULL, which is
		// what the column means when the value was never supplied.
		if item.Value != "" {
			entry["value"] = item.Value
		}
		encoded = append(encoded, entry)
	}
	body, err := json.Marshal(map[string]any{
		"warehouse_id":    strings.TrimPrefix(c.settings.DatabricksHTTPPath, "/sql/1.0/warehouses/"),
		"statement":       statement,
		"wait_timeout":    "30s",
		"on_wait_timeout": "CANCEL",
		"format":          "JSON_ARRAY",
		"disposition":     "INLINE",
		"parameters":      encoded,
	})
	if err != nil {
		return nil, errors.New("unable to encode the Databricks statement")
	}

	request, err := http.NewRequest(http.MethodPost,
		c.BaseURL()+"/api/2.0/sql/statements", bytes.NewReader(body))
	if err != nil {
		return nil, errors.New("unable to build the Databricks request")
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")

	response, err := c.http.Do(request)
	if err != nil {
		return nil, errors.New("Databricks statement execution failed")
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 32<<20))
	if err != nil {
		return nil, errors.New("Databricks response could not be read")
	}
	if response.StatusCode != http.StatusOK {
		// The response body may echo the statement; never surface it.
		return nil, fmt.Errorf("Databricks returned HTTP %d", response.StatusCode)
	}
	var decoded statementResponse
	if err := json.Unmarshal(payload, &decoded); err != nil {
		return nil, errors.New("Databricks response was not valid JSON")
	}
	if decoded.Status.State != "SUCCEEDED" {
		code := "-"
		if decoded.Status.Error != nil {
			code = decoded.Status.Error.ErrorCode
		}
		return nil, fmt.Errorf("Databricks statement did not succeed (state=%s code=%s)",
			decoded.Status.State, code)
	}
	if decoded.Result == nil {
		return nil, nil
	}
	return decoded.Result.DataArray, nil
}

// accessToken returns a bearer token, minting and caching an OAuth M2M token
// when the deployment uses a service principal.
func (c *Client) accessToken() (string, error) {
	if c.settings.NormalizedDatabricksAuthType() == "pat" {
		if strings.TrimSpace(c.settings.DatabricksToken) == "" {
			return "", errors.New("Databricks PAT configuration is incomplete")
		}
		return c.settings.DatabricksToken, nil
	}

	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	if c.token != "" && time.Now().Before(c.tokenExpiry) {
		return c.token, nil
	}
	if c.settings.DatabricksClientID == "" || c.settings.DatabricksClientSecret == "" {
		return "", errors.New("Databricks OAuth configuration is incomplete")
	}
	form := url.Values{"grant_type": {"client_credentials"}, "scope": {"all-apis"}}
	request, err := http.NewRequest(http.MethodPost,
		c.BaseURL()+"/oidc/v1/token", strings.NewReader(form.Encode()))
	if err != nil {
		return "", errors.New("unable to build the Databricks token request")
	}
	request.SetBasicAuth(c.settings.DatabricksClientID, c.settings.DatabricksClientSecret)
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	response, err := c.http.Do(request)
	if err != nil {
		return "", errors.New("Databricks token request failed")
	}
	defer func() { _ = response.Body.Close() }()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil || response.StatusCode != http.StatusOK {
		return "", errors.New("Databricks token request was rejected")
	}
	var token struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(payload, &token); err != nil || token.AccessToken == "" {
		return "", errors.New("Databricks token response was invalid")
	}
	c.token = token.AccessToken
	lifetime := time.Duration(token.ExpiresIn) * time.Second
	if lifetime <= 0 {
		lifetime = 10 * time.Minute
	}
	// Refresh early so an in-flight read never races the expiry.
	c.tokenExpiry = time.Now().Add(lifetime - 60*time.Second)
	return c.token, nil
}

// QuoteTable renders a fully qualified table name, rejecting any identifier
// that is not a plain word so a reference can never inject SQL.
func QuoteTable(catalog, schema, table string) (string, error) {
	parts := []struct{ value, label string }{
		{catalog, "catalog"}, {schema, "schema"}, {table, "table"},
	}
	quoted := make([]string, 0, len(parts))
	for _, part := range parts {
		if !identifierPattern.MatchString(part.value) {
			return "", fmt.Errorf("%s is not a valid Databricks identifier", part.label)
		}
		quoted = append(quoted, "`"+part.value+"`")
	}
	return strings.Join(quoted, "."), nil
}

// Text safely dereferences a nullable column value.
func Text(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
