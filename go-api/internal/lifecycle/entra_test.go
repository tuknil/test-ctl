package lifecycle

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ATT-CSO/control-translation/go-api/internal/config"
)

// Azure Database for PostgreSQL takes an Entra access token as the password.
// The token expires, so the interesting behaviour is when a new one is minted
// and what happens to the client secret when minting fails.

const testSecret = "super-secret-value"

// tokenEndpoint stands in for Entra, recording what was sent to it.
type tokenEndpoint struct {
	server *httptest.Server

	mutex     sync.Mutex
	requests  []url.Values
	token     string
	expiresIn int
	status    int
	body      string
	// raw, when set, is written verbatim whatever the status, so a test can
	// serve a malformed success body.
	raw *string
}

func newTokenEndpoint(t *testing.T) *tokenEndpoint {
	t.Helper()
	endpoint := &tokenEndpoint{token: "token-1", expiresIn: 3600, status: http.StatusOK}
	endpoint.server = httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			endpoint.mutex.Lock()
			endpoint.requests = append(endpoint.requests, r.PostForm)
			status, body := endpoint.status, endpoint.body
			token, expiresIn, raw := endpoint.token, endpoint.expiresIn, endpoint.raw
			endpoint.mutex.Unlock()

			w.Header().Set("Content-Type", "application/json")
			if raw != nil {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(*raw))
				return
			}
			if status != http.StatusOK {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(body))
				return
			}
			_, _ = fmt.Fprintf(w, `{"access_token":%q,"expires_in":%d,"token_type":"Bearer"}`,
				token, expiresIn)
		}))
	t.Cleanup(endpoint.server.Close)
	return endpoint
}

func (e *tokenEndpoint) calls() int {
	e.mutex.Lock()
	defer e.mutex.Unlock()
	return len(e.requests)
}

func (e *tokenEndpoint) lastRequest(t *testing.T) url.Values {
	t.Helper()
	e.mutex.Lock()
	defer e.mutex.Unlock()
	if len(e.requests) == 0 {
		t.Fatal("the token endpoint was never called")
	}
	return e.requests[len(e.requests)-1]
}

func newSource(endpoint *tokenEndpoint) *EntraTokenSource {
	source := NewEntraTokenSource("tenant-1", "client-1", testSecret,
		"https://ossrdbms-aad.database.windows.net/.default")
	source.Endpoint = endpoint.server.URL
	return source
}

func TestATokenIsMintedByClientCredentials(t *testing.T) {
	endpoint := newTokenEndpoint(t)

	token, err := newSource(endpoint).Token(context.Background())
	if err != nil {
		t.Fatalf("token failed: %v", err)
	}
	if token != "token-1" {
		t.Errorf("token = %q, want token-1", token)
	}

	form := endpoint.lastRequest(t)
	if form.Get("grant_type") != "client_credentials" {
		t.Errorf("grant_type = %q", form.Get("grant_type"))
	}
	if form.Get("client_id") != "client-1" || form.Get("client_secret") != testSecret {
		t.Error("the principal was not sent")
	}
	// The scope is what makes the token usable as a Postgres password rather
	// than as a token for some other Azure resource.
	if form.Get("scope") != "https://ossrdbms-aad.database.windows.net/.default" {
		t.Errorf("scope = %q", form.Get("scope"))
	}
}

// A token lasts about an hour, and the pool opens connections continuously.
// Fetching one per connection would put Entra in the path of every reconnect.
func TestAValidTokenIsReusedRatherThanRefetched(t *testing.T) {
	endpoint := newTokenEndpoint(t)
	source := newSource(endpoint)

	for attempt := 0; attempt < 5; attempt++ {
		if _, err := source.Token(context.Background()); err != nil {
			t.Fatalf("token failed: %v", err)
		}
	}

	if endpoint.calls() != 1 {
		t.Errorf("the endpoint was called %d times for one valid token", endpoint.calls())
	}
}

// A token close to expiry is replaced before it expires, so a connection
// opening at the boundary does not race it.
func TestATokenNearingExpiryIsReplaced(t *testing.T) {
	endpoint := newTokenEndpoint(t)
	// Shorter than the renewal margin, so the first token is never reusable.
	endpoint.expiresIn = int((tokenRenewalMargin - time.Minute).Seconds())
	source := newSource(endpoint)

	first, err := source.Token(context.Background())
	if err != nil {
		t.Fatalf("first token failed: %v", err)
	}
	endpoint.mutex.Lock()
	endpoint.token = "token-2"
	endpoint.mutex.Unlock()

	second, err := source.Token(context.Background())
	if err != nil {
		t.Fatalf("second token failed: %v", err)
	}

	if first == second {
		t.Error("a token inside the renewal margin was reused")
	}
	if second != "token-2" {
		t.Errorf("token = %q, want the freshly minted token-2", second)
	}
}

// Concurrent connections must not each mint their own token.
func TestConcurrentCallersShareOneToken(t *testing.T) {
	endpoint := newTokenEndpoint(t)
	source := newSource(endpoint)

	var group sync.WaitGroup
	for caller := 0; caller < 16; caller++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := source.Token(context.Background()); err != nil {
				t.Errorf("token failed: %v", err)
			}
		}()
	}
	group.Wait()

	if endpoint.calls() != 1 {
		t.Errorf("%d concurrent callers minted %d tokens, want 1", 16, endpoint.calls())
	}
}

// Every misconfiguration here looks the same from the outside -- wrong tenant,
// wrong secret, principal without access -- so the description Entra returns is
// worth keeping. This body is the shape a real endpoint returns: the AADSTS
// code and its sentence, then the trace and correlation ids inline, which are
// the identifiers Microsoft support asks for.
func TestAFailedTokenExplainsWhyWithoutLeakingTheSecret(t *testing.T) {
	endpoint := newTokenEndpoint(t)
	endpoint.status = http.StatusBadRequest
	endpoint.body = `{"error":"invalid_request","error_description":` +
		`"AADSTS900023: Specified tenant identifier 'wrong' is neither a valid DNS name, ` +
		`nor a valid external domain. Trace ID: 91752d89-32c0-422b-8e22-8a7d5787be00 ` +
		`Correlation ID: ebd7b733-0fdf-4530-ab37-69ebb2e982e2 Timestamp: 2026-09-17 22:14:43Z"}`

	_, err := newSource(endpoint).Token(context.Background())

	if err == nil {
		t.Fatal("a rejected token request should fail")
	}
	message := err.Error()
	if strings.Contains(message, testSecret) {
		t.Error("the client secret appeared in the error")
	}
	if !strings.Contains(message, "invalid_request") ||
		!strings.Contains(message, "AADSTS900023") {
		t.Errorf("the error should say why Entra refused: %v", err)
	}
	// The trace id is the point of keeping the description at all.
	if !strings.Contains(message, "91752d89-32c0-422b-8e22-8a7d5787be00") {
		t.Errorf("the trace id was dropped: %v", err)
	}
}

// A newline in a log line can forge a second entry, so they are folded to
// spaces rather than passed through.
func TestAFailedTokenCannotInjectLinesIntoTheLog(t *testing.T) {
	endpoint := newTokenEndpoint(t)
	endpoint.status = http.StatusUnauthorized
	endpoint.body = "{\"error\":\"invalid_client\",\"error_description\":" +
		"\"Invalid client secret.\\r\\nlevel=INFO msg=\\\"all clear\\\"\"}"

	_, err := newSource(endpoint).Token(context.Background())

	if err == nil {
		t.Fatal("a rejected token request should fail")
	}
	if strings.ContainsAny(err.Error(), "\r\n") {
		t.Errorf("a newline survived into the message: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "Invalid client secret.") {
		t.Errorf("folding lost the description: %v", err)
	}
}

// A description long enough to bury a log line is bounded.
func TestAnEnormousDescriptionIsTruncated(t *testing.T) {
	endpoint := newTokenEndpoint(t)
	endpoint.status = http.StatusBadRequest
	endpoint.body = `{"error":"invalid_request","error_description":"` +
		strings.Repeat("x", 5000) + `"}`

	_, err := newSource(endpoint).Token(context.Background())

	if err == nil {
		t.Fatal("a rejected token request should fail")
	}
	if len(err.Error()) > maxDescription+300 {
		t.Errorf("the message is %d characters; it should be bounded", len(err.Error()))
	}
}

// A 200 that does not actually carry a usable token must not be treated as a
// password: an empty password against Postgres fails later and further away.
func TestAnUnusableTokenResponseIsRejected(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
	}{
		"no access_token":    {http.StatusOK, `{"expires_in":3600}`},
		"empty access_token": {http.StatusOK, `{"access_token":"","expires_in":3600}`},
		"not json":           {http.StatusOK, `<html>error</html>`},
	}
	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			endpoint := newTokenEndpoint(t)
			endpoint.raw = &testCase.body
			endpoint.status = testCase.status

			if _, err := newSource(endpoint).Token(context.Background()); err == nil {
				t.Error("an unusable token response should fail")
			}
		})
	}
}

// A response with no lifetime is not cached indefinitely.
func TestATokenWithNoStatedLifetimeIsNotCachedForever(t *testing.T) {
	endpoint := newTokenEndpoint(t)
	endpoint.expiresIn = 0
	source := newSource(endpoint)

	if _, err := source.Token(context.Background()); err != nil {
		t.Fatalf("token failed: %v", err)
	}
	if _, err := source.Token(context.Background()); err != nil {
		t.Fatalf("second token failed: %v", err)
	}

	if endpoint.calls() < 2 {
		t.Error("a token with no stated lifetime was cached")
	}
}

// The default endpoint is the tenant's, which is what a deployment without an
// override has to reach.
func TestTheDefaultEndpointIsTheTenantsTokenEndpoint(t *testing.T) {
	source := NewEntraTokenSource("my-tenant", "client", "secret", "scope")

	if got := source.endpoint(); got !=
		"https://login.microsoftonline.com/my-tenant/oauth2/v2.0/token" {
		t.Errorf("endpoint = %s", got)
	}
}

// ---------------------------------------------------------------------------
// Connection string
// ---------------------------------------------------------------------------

func entraSettings() config.Settings {
	return config.Settings{
		DatabaseAuthMode: config.AuthModeEntra,
		DatabaseURL: "postgres://janus-app@janus.postgres.database.azure.com:5432" +
			"/control_translation?sslmode=verify-full",
	}
}

// The connection string is DATABASE_URL as the operator wrote it. The only
// addition is an application_name, so a session holding a queue lock is
// identifiable in pg_stat_activity.
func TestTheConnectionStringIsTheConfiguredURL(t *testing.T) {
	parsed, err := url.Parse(connectionString(entraSettings()))
	if err != nil {
		t.Fatalf("the connection string is not a URL: %v", err)
	}

	if parsed.Host != "janus.postgres.database.azure.com:5432" {
		t.Errorf("host = %s", parsed.Host)
	}
	if parsed.Path != "/control_translation" {
		t.Errorf("database = %s", parsed.Path)
	}
	if parsed.User.Username() != "janus-app" {
		t.Errorf("user = %s", parsed.User.Username())
	}
	if got := parsed.Query().Get("sslmode"); got != "verify-full" {
		t.Errorf("sslmode = %q, want the mode the URL set", got)
	}
	if got := parsed.Query().Get("application_name"); got != "control-translation-go" {
		t.Errorf("application_name = %q", got)
	}
}

// Whatever the URL already carries is left alone: it is the operator's string,
// not a set of parts to reassemble.
func TestTheConnectionStringPreservesTheURLsOwnParameters(t *testing.T) {
	settings := entraSettings()
	settings.DatabaseURL = "postgres://janus-app@host:5432/db" +
		"?sslmode=verify-ca&connect_timeout=8&application_name=set-by-operator"

	parsed, err := url.Parse(connectionString(settings))
	if err != nil {
		t.Fatalf("the connection string is not a URL: %v", err)
	}
	query := parsed.Query()

	if query.Get("connect_timeout") != "8" {
		t.Errorf("an unrelated parameter was dropped: %v", query)
	}
	if query.Get("sslmode") != "verify-ca" {
		t.Errorf("sslmode was rewritten to %q", query.Get("sslmode"))
	}
	// An application_name the operator chose is theirs to keep.
	if query.Get("application_name") != "set-by-operator" {
		t.Errorf("application_name was overwritten: %q", query.Get("application_name"))
	}
}

// A password in the URL is meaningless on the Entra path -- the password is a
// token minted per connection -- and leaving a stale one in place would only
// produce a confusing authentication failure.
func TestAPasswordInTheURLIsDroppedOnTheEntraPath(t *testing.T) {
	settings := entraSettings()
	settings.DatabaseURL = "postgres://janus-app:leftover-secret@host:5432/db?sslmode=verify-full"

	built := connectionString(settings)

	if strings.Contains(built, "leftover-secret") {
		t.Errorf("a stale password survived into the connection string: %s", built)
	}
	parsed, _ := url.Parse(built)
	if parsed.User.Username() != "janus-app" {
		t.Errorf("the user was dropped along with the password: %q", parsed.User.Username())
	}
}

// The password path uses the URL exactly as given, password and all.
func TestThePasswordPathKeepsTheURLsCredential(t *testing.T) {
	settings := entraSettings()
	settings.DatabaseAuthMode = config.AuthModePassword
	settings.DatabaseURL = "postgres://app:local-secret@127.0.0.1:55432/db?sslmode=disable"

	parsed, err := url.Parse(connectionString(settings))
	if err != nil {
		t.Fatalf("the connection string is not a URL: %v", err)
	}

	password, set := parsed.User.Password()
	if !set || password != "local-secret" {
		t.Error("the password path dropped the URL's own credential")
	}
	if got := parsed.Query().Get("sslmode"); got != "disable" {
		t.Errorf("sslmode = %q; the password path does not rewrite it", got)
	}
}

// The password path mints nothing: the credential is already in the URL.
func TestThePasswordModeNeedsNoTokenSource(t *testing.T) {
	settings := entraSettings()
	settings.DatabaseAuthMode = config.AuthModePassword

	if source := tokenSourceFor(settings); source != nil {
		t.Errorf("password mode built a token source: %T", source)
	}
}

func TestTheEntraModeMintsTokens(t *testing.T) {
	if _, isEntra := tokenSourceFor(entraSettings()).(*EntraTokenSource); !isEntra {
		t.Error("entra mode should use the Entra token source")
	}
}
