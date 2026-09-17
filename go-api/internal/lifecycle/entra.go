package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Azure Database for PostgreSQL accepts an Entra access token in place of a
// password. The token is short-lived -- an hour, typically -- so it cannot be
// configured like a password: it is minted before each connection and reused
// from memory until shortly before it expires.
//
// Only the client-credentials flow is implemented, which is what
// AZURE_CLIENT_ID and AZURE_CLIENT_SECRET describe. Managed identity would be
// a second TokenSource, not a change to the caller.

// TokenSource hands out a bearer token to use as the database password.
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// staticToken is the password path: a secret that never expires.
type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

// A token is renewed this long before it actually expires, so a connection
// opening at the boundary does not race the expiry.
const tokenRenewalMargin = 5 * time.Minute

// EntraTokenSource mints Entra access tokens by client credentials and caches
// the current one.
type EntraTokenSource struct {
	tenantID     string
	clientID     string
	clientSecret string
	scope        string

	// Endpoint is the token endpoint, overridable so the flow can be tested
	// without reaching Microsoft.
	Endpoint string
	Client   *http.Client

	mutex   sync.Mutex
	token   string
	expires time.Time
}

// NewEntraTokenSource builds a token source for the configured principal.
func NewEntraTokenSource(tenantID, clientID, clientSecret, scope string) *EntraTokenSource {
	return &EntraTokenSource{
		tenantID: tenantID, clientID: clientID, clientSecret: clientSecret, scope: scope,
		Client: &http.Client{Timeout: 30 * time.Second},
	}
}

func (e *EntraTokenSource) endpoint() string {
	if e.Endpoint != "" {
		return e.Endpoint
	}
	return fmt.Sprintf("https://login.microsoftonline.com/%s/oauth2/v2.0/token",
		url.PathEscape(e.tenantID))
}

// Token returns a cached token when one is still comfortably valid, and
// otherwise fetches a new one.
func (e *EntraTokenSource) Token(ctx context.Context) (string, error) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	if e.token != "" && time.Now().Before(e.expires.Add(-tokenRenewalMargin)) {
		return e.token, nil
	}

	token, lifetime, err := e.fetch(ctx)
	if err != nil {
		// The secret is in the request, never in the error.
		return "", fmt.Errorf("%w: entra-token: %v", ErrStore, err)
	}
	e.token = token
	e.expires = time.Now().Add(lifetime)
	return token, nil
}

func (e *EntraTokenSource) fetch(ctx context.Context) (string, time.Duration, error) {
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {e.clientID},
		"client_secret": {e.clientSecret},
		"scope":         {e.scope},
	}
	request, err := http.NewRequestWithContext(
		ctx, http.MethodPost, e.endpoint(), strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := e.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", 0, err
	}
	if response.StatusCode != http.StatusOK {
		// Entra puts a description in the body. It names the principal and the
		// failure, and carries no secret, so it is worth keeping: without it
		// every misconfiguration looks identical.
		return "", 0, fmt.Errorf("token endpoint returned %d: %s",
			response.StatusCode, summarizeTokenError(body))
	}

	var decoded struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		return "", 0, fmt.Errorf("token endpoint returned a response that is not JSON")
	}
	if decoded.AccessToken == "" {
		return "", 0, fmt.Errorf("token endpoint returned no access_token")
	}
	lifetime := time.Duration(decoded.ExpiresIn) * time.Second
	if lifetime <= 0 {
		// Treat an absent lifetime as one that has to be refetched rather than
		// caching a token forever.
		lifetime = tokenRenewalMargin
	}
	return decoded.AccessToken, lifetime, nil
}

// summarizeTokenError pulls the error fields out of a failed token response
// and leaves the rest of the body out.
//
// The description is kept whole. A real AADSTS description carries the trace
// and correlation ids inline -- "AADSTS900023: ... Trace ID: <id>
// Correlation ID: <id>" -- and those are the identifiers Microsoft support
// asks for, so dropping them would throw away the useful half of the message.
// Newlines are folded to spaces rather than cut: a newline in a log line can
// forge a second entry, and nothing is gained by splitting the message.
func summarizeTokenError(body []byte) string {
	var decoded struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil || decoded.Error == "" {
		return "unrecognized error response"
	}
	description := foldLines(decoded.Description)
	if description == "" {
		return decoded.Error
	}
	if len(description) > maxDescription {
		description = description[:maxDescription] + "..."
	}
	return decoded.Error + ": " + description
}

// maxDescription bounds how much of a token endpoint's prose reaches a log
// line. Long enough for an AADSTS code, its sentence and the trace ids.
const maxDescription = 400

func foldLines(text string) string {
	return strings.TrimSpace(strings.Join(strings.FieldsFunc(text, func(r rune) bool {
		return r == '\r' || r == '\n'
	}), " "))
}
