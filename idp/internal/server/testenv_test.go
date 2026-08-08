package server_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aikazzh/portfolio/idp/internal/oauth"
	"github.com/aikazzh/portfolio/idp/internal/password"
	"github.com/aikazzh/portfolio/idp/internal/server"
	"github.com/aikazzh/portfolio/idp/internal/storage"
	"github.com/aikazzh/portfolio/idp/internal/storage/memory"
	ksclient "github.com/aikazzh/portfolio/keysmith/client"
	"github.com/aikazzh/portfolio/keysmith/jose"
	"github.com/aikazzh/portfolio/keysmith/keystore"
	ksservice "github.com/aikazzh/portfolio/keysmith/service"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// env is a fully wired idp + keysmith test environment.
type env struct {
	t      *testing.T
	clock  *clock
	store  storage.Store
	signer *tokenSigner
	idp    *httptest.Server
	// client follows no redirects and carries a cookie jar.
	client *http.Client
}

const (
	testUserPassword = "s3cure-passw0rd!"
	webAppSecret     = "web-app-secret-value"
)

func newEnv(t *testing.T) *env { return newEnvOpts(t, true) }

// newEnvOpts builds the environment with InsecureDev configurable: httptest
// serves plain HTTP so tests want dev mode, but the cookie-hardening test needs
// the production cookie shape.
func newEnvOpts(t *testing.T, insecureDev bool) *env {
	t.Helper()
	ck := &clock{t: time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)}

	// Real keysmith, in process.
	ksCfg := keystore.Config{
		Algorithms:   []jose.Algorithm{jose.AlgEdDSA},
		PendingDwell: 10 * time.Minute,
		MaxKeyAge:    24 * time.Hour,
		RetireAfter:  2 * time.Hour,
		Now:          ck.Now,
	}
	manager, err := keystore.NewManager(keystore.NewMemoryStore(), ksCfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.Tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	ksSvc, err := ksservice.New(manager, ksCfg, ksservice.Config{
		SignerTokens: []string{"test-signer"},
		MaxTokenTTL:  time.Hour,
		JWKSMaxAge:   5 * time.Minute,
		Now:          ck.Now,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	ksSrv := httptest.NewServer(ksSvc.Handler())
	t.Cleanup(ksSrv.Close)
	ks := ksclient.New(ksSrv.URL, "test-signer", ksclient.WithClock(ck.Now))

	store := memory.New()
	signer := &tokenSigner{c: ks}
	e := &env{t: t, clock: ck, store: store, signer: signer}

	// idp server; BaseURL must equal the httptest URL for issuer checks,
	// so create the server after the listener exists.
	var idpSrv *server.Server
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		idpSrv.Handler().ServeHTTP(w, r)
	})
	e.idp = httptest.NewServer(handler)
	t.Cleanup(e.idp.Close)

	idpSrv, err = server.New(server.Config{
		BaseURL:           e.idp.URL,
		Store:             store,
		Signer:            signer,
		Keysmith:          ks,
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		RegistrationToken: "test-registration-token",
		InsecureDev:       insecureDev, // httptest is plain HTTP
		Now:               ck.Now,
	})
	if err != nil {
		t.Fatal(err)
	}

	e.seed()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	e.client = &http.Client{
		Jar: jar,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return e
}

type tokenSigner struct {
	c    *ksclient.Client
	fail atomic.Bool // when set, Sign fails — simulates a keysmith outage
}

func (s *tokenSigner) Sign(ctx context.Context, claims jose.Claims, ttl time.Duration) (string, error) {
	if s.fail.Load() {
		return "", errors.New("keysmith unavailable")
	}
	return s.c.Sign(ctx, ksclient.SignRequest{Claims: claims, TTLSeconds: int64(ttl.Seconds())})
}

func (e *env) seed() {
	e.t.Helper()
	ctx := context.Background()
	now := e.clock.Now()
	must := func(err error) {
		if err != nil {
			e.t.Fatal(err)
		}
	}
	must(e.store.Realms().Create(ctx, storage.Realm{
		Name: "test", DisplayName: "Test Realm",
		AccessTokenTTL:  10 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
		SessionTTL:      8 * time.Hour,
		CreatedAt:       now,
	}))
	hash, err := password.Hash(testUserPassword, password.Params{
		MemoryKiB: 1024, Iterations: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32, // fast for tests
	})
	must(err)
	must(e.store.Users().Create(ctx, storage.User{
		ID: "usr_1", RealmName: "test",
		Username: "alice", Email: "alice@example.com", EmailVerified: true,
		PasswordHash: hash, Name: "Alice Liddell", GivenName: "Alice", FamilyName: "Liddell",
		CreatedAt: now, UpdatedAt: now,
	}))
	secretHash := sha256.Sum256([]byte(webAppSecret))
	must(e.store.Clients().Create(ctx, storage.Client{
		RealmName: "test", ClientID: "web-app", SecretHash: secretHash[:],
		Name:         "Test Web App",
		RedirectURIs: []string{"https://app.example/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       oauth.Scopes{"openid", "profile", "email", "offline_access"},
		CreatedAt:    now,
	}))
	must(e.store.Clients().Create(ctx, storage.Client{
		RealmName: "test", ClientID: "spa", Public: true,
		Name:         "Test SPA",
		RedirectURIs: []string{"https://spa.example/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       oauth.Scopes{"openid", "profile", "email", "offline_access"},
		CreatedAt:    now,
	}))
	must(e.store.Clients().Create(ctx, storage.Client{
		RealmName: "test", ClientID: "cli", Public: true,
		Name:       "Test CLI",
		GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code"},
		Scopes:     oauth.Scopes{"openid", "profile", "offline_access"},
		CreatedAt:  now,
	}))
	must(e.store.Clients().Create(ctx, storage.Client{
		RealmName: "test", ClientID: "service", SecretHash: secretHash[:],
		Name:       "Test Service",
		GrantTypes: []string{"client_credentials"},
		Scopes:     oauth.Scopes{"inventory:read"},
		CreatedAt:  now,
	}))
	// A first-party confidential client (skips consent).
	must(e.store.Clients().Create(ctx, storage.Client{
		RealmName: "test", ClientID: "portal", SecretHash: secretHash[:],
		Name: "First Party Portal", FirstParty: true,
		RedirectURIs: []string{"https://portal.example/callback"},
		GrantTypes:   []string{"authorization_code", "refresh_token"},
		Scopes:       oauth.Scopes{"openid", "profile", "email", "offline_access"},
		CreatedAt:    now,
	}))
}

var (
	csrfRe     = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
	returnToRe = regexp.MustCompile(`name="return_to" value="([^"]+)"`)
)

func (e *env) get(path string) (*http.Response, string) {
	e.t.Helper()
	resp, err := e.client.Get(e.idp.URL + path)
	if err != nil {
		e.t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		e.t.Fatal(err)
	}
	return resp, string(body)
}

func (e *env) postForm(path string, form url.Values) (*http.Response, string) {
	e.t.Helper()
	resp, err := e.client.PostForm(e.idp.URL+path, form)
	if err != nil {
		e.t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		e.t.Fatal(err)
	}
	return resp, string(body)
}

// authorizeURL builds an authorize request URL for the test realm.
func authorizeURL(params map[string]string) string {
	q := url.Values{}
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	return "/realms/test/authorize?" + q.Encode()
}

// pkcePair returns a valid verifier and its S256 challenge.
func pkcePair() (verifier, challenge string) {
	verifier = strings.Repeat("a1b2c3d4", 6) // 48 chars, valid charset
	sum := sha256.Sum256([]byte(verifier))
	return verifier, base64.RawURLEncoding.EncodeToString(sum[:])
}

// login drives the login form from an authorize response body.
func (e *env) login(body, username, pass string) (*http.Response, string) {
	e.t.Helper()
	csrf := csrfRe.FindStringSubmatch(body)
	ret := returnToRe.FindStringSubmatch(body)
	if csrf == nil || ret == nil {
		e.t.Fatalf("login page missing csrf/return_to:\n%s", body)
	}
	// A browser HTML-decodes attribute values before submitting them.
	return e.postForm("/realms/test/login", url.Values{
		"csrf_token": {html.UnescapeString(csrf[1])},
		"return_to":  {html.UnescapeString(ret[1])},
		"username":   {username},
		"password":   {pass},
	})
}

// consent drives the consent form.
func (e *env) consent(body, decision string) (*http.Response, string) {
	e.t.Helper()
	csrf := csrfRe.FindStringSubmatch(body)
	ret := returnToRe.FindStringSubmatch(body)
	if csrf == nil || ret == nil {
		e.t.Fatalf("consent page missing csrf/return_to:\n%s", body)
	}
	return e.postForm("/realms/test/consent", url.Values{
		"csrf_token": {html.UnescapeString(csrf[1])},
		"return_to":  {html.UnescapeString(ret[1])},
		"decision":   {decision},
	})
}

// obtainCode runs the full browser dance and returns the authorization code.
// Assumes the confidential "web-app" client unless params overrides.
func (e *env) obtainCode(params map[string]string) string {
	e.t.Helper()
	base := map[string]string{
		"client_id":     "web-app",
		"redirect_uri":  "https://app.example/callback",
		"response_type": "code",
		"scope":         "openid profile email offline_access",
		"state":         "st4te",
		"nonce":         "n0nce",
	}
	for k, v := range params {
		base[k] = v
	}
	resp, body := e.get(authorizeURL(base))
	// Login if presented.
	if resp.StatusCode == http.StatusOK && strings.Contains(body, "Sign in") {
		resp, body = e.login(body, "alice", testUserPassword)
		if resp.StatusCode != http.StatusSeeOther {
			e.t.Fatalf("login: status %d: %s", resp.StatusCode, body)
		}
		resp, body = e.get(resp.Header.Get("Location"))
	}
	// Consent if presented.
	if resp.StatusCode == http.StatusOK && strings.Contains(body, "requests access") {
		resp, body = e.consent(body, "allow")
		if resp.StatusCode != http.StatusSeeOther {
			e.t.Fatalf("consent: status %d: %s", resp.StatusCode, body)
		}
		resp, body = e.get(resp.Header.Get("Location"))
	}
	if resp.StatusCode != http.StatusFound {
		e.t.Fatalf("authorize final: status %d: %s", resp.StatusCode, body)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		e.t.Fatal(err)
	}
	if got := loc.Query().Get("error"); got != "" {
		e.t.Fatalf("authorize error: %s (%s)", got, loc.Query().Get("error_description"))
	}
	if loc.Query().Get("state") != base["state"] {
		e.t.Fatalf("state mismatch: %q", loc.Query().Get("state"))
	}
	code := loc.Query().Get("code")
	if code == "" {
		e.t.Fatalf("no code in redirect: %s", loc)
	}
	return code
}

// tokenRequest posts to the token endpoint with Basic client auth.
func (e *env) tokenRequest(clientID, clientSecret string, form url.Values) (int, map[string]any) {
	e.t.Helper()
	req, err := http.NewRequest("POST", e.idp.URL+"/realms/test/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		e.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID != "" {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	}
	resp, err := e.client.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil && err != io.EOF {
		e.t.Fatal(err)
	}
	return resp.StatusCode, out
}

// exchangeCode redeems a code for tokens via the confidential client.
func (e *env) exchangeCode(code string) map[string]any {
	e.t.Helper()
	status, body := e.tokenRequest("web-app", webAppSecret, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"https://app.example/callback"},
	})
	if status != http.StatusOK {
		e.t.Fatalf("token exchange: %d: %v", status, body)
	}
	return body
}

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

func sha256Of(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// jwtPayload decodes the payload segment of a JWT for content assertions.
func jwtPayload(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// registerClient calls the RFC 7591 endpoint with the test registration token.
func registerClient(t *testing.T, e *env, metadata map[string]any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest("POST", e.idp.URL+"/realms/test/register", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer test-registration-token")
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil && err != io.EOF {
		t.Fatal(err)
	}
	return resp.StatusCode, out
}
