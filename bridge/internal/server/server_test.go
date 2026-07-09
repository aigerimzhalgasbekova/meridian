package server

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aikazzh/portfolio/bridge/internal/directory"
	"github.com/aikazzh/portfolio/bridge/internal/fakeidp"
	"github.com/aikazzh/portfolio/bridge/internal/health"
	"github.com/aikazzh/portfolio/bridge/internal/provider"
	"github.com/aikazzh/portfolio/keysmith/jose"
)

// clock is a mutable test clock safe for concurrent reads from the server.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// env is a fully wired bridge with two fake upstreams.
type env struct {
	srv    *httptest.Server
	alpha  *fakeidp.Server
	beta   *fakeidp.Server
	store  *directory.MemStore
	verKey jose.VerificationKey
	clock  *clock
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ck := &clock{t: time.Now()}
	alpha := fakeidp.New("cid-alpha", "sec-alpha", fakeidp.User{Subject: "sub-a", Email: "alice@example.com", Name: "Alice A"})
	t.Cleanup(alpha.Close)
	beta := fakeidp.New("cid-beta", "sec-beta", fakeidp.User{Subject: "sub-b", Email: "alice@example.com", Name: "Alice B"})
	t.Cleanup(beta.Close)

	newP := func(name, issuer, cid, sec string) *provider.Provider {
		p, err := provider.New(provider.Config{
			Name: name, DisplayName: strings.ToUpper(name), Issuer: issuer,
			ClientID: cid, ClientSecret: sec,
		}, provider.WithClock(ck.now), provider.WithBreaker(health.New(1, time.Minute, ck.now)))
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	reg, err := provider.NewRegistry(
		newP("alpha", alpha.URL, "cid-alpha", "sec-alpha"),
		newP("beta", beta.URL, "cid-beta", "sec-beta"),
	)
	if err != nil {
		t.Fatal(err)
	}
	store := directory.NewMemStore(ck.now)
	signer, verKey, err := NewLocalSigner()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(nil) // reserve the port to learn BaseURL first
	s, err := New(Config{
		BaseURL:     srv.URL,
		HMACKey:     []byte(strings.Repeat("k", 32)),
		Apps:        map[string]App{"demo": {Name: "Demo", CallbackURL: "http://app.example/cb"}},
		InsecureDev: true,
		Now:         ck.now,
	}, reg, store, signer)
	if err != nil {
		t.Fatal(err)
	}
	srv.Config.Handler = s
	t.Cleanup(srv.Close)
	return &env{srv: srv, alpha: alpha, beta: beta, store: store, verKey: verKey, clock: ck}
}

// client returns an HTTP client with a cookie jar that follows redirects
// except onto the registered app host.
func (e *env) client(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Host == "app.example" {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func get(t *testing.T, c *http.Client, u string) (*http.Response, string) {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

func TestLoginHappyPath(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)

	resp, body := get(t, c, e.srv.URL+"/login/alpha")
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Request.URL.Path, "/account") {
		t.Fatalf("expected to land on /account, got %d at %s", resp.StatusCode, resp.Request.URL)
	}
	if !strings.Contains(body, "Alice A") || !strings.Contains(body, "sub-a") {
		t.Fatalf("account page missing identity: %s", body)
	}
	// Second login resolves to the same identity, not a new one.
	c2 := e.client(t)
	_, body2 := get(t, c2, e.srv.URL+"/login/alpha")
	var id1, id2 string
	for _, pair := range [][2]*string{{&body, &id1}, {&body2, &id2}} {
		i := strings.Index(*pair[0], "idn_")
		if i < 0 {
			t.Fatalf("no identity id on page")
		}
		*pair[1] = (*pair[0])[i : i+10]
	}
	if id1 != id2 {
		t.Fatalf("repeat login provisioned a second identity: %s vs %s", id1, id2)
	}
}

func TestAssertionDelivery(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)

	resp, _ := get(t, c, e.srv.URL+"/login/alpha?app=demo")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect to app callback, got %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loc.Scheme+"://"+loc.Host+loc.Path != "http://app.example/cb" {
		t.Fatalf("assertion delivered to %q, not the registered callback", loc)
	}
	token := loc.Query().Get("assertion")
	set, err := jose.NewKeySet(e.verKey)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := jose.VerifyClaims(token, set, []jose.Algorithm{jose.AlgEdDSA}, jose.Expect{
		Issuer: e.srv.URL, Audience: "demo", Now: e.clock.now,
	})
	if err != nil {
		t.Fatalf("assertion failed verification: %v", err)
	}
	if !strings.HasPrefix(claims.Subject, "idn_") {
		t.Fatalf("assertion sub should be the bridge id, got %q", claims.Subject)
	}
	if claims.Extra["idp"] != "alpha" || claims.Extra["email"] != "alice@example.com" {
		t.Fatalf("normalized claims wrong: %+v", claims.Extra)
	}
	if claims.ExpiresAt-claims.IssuedAt != int64(AssertionTTL/time.Second) {
		t.Fatalf("assertion TTL = %ds", claims.ExpiresAt-claims.IssuedAt)
	}
}

func TestStateReplayRejected(t *testing.T) {
	e := newEnv(t)
	noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	resp, _ := get(t, noRedirect, e.srv.URL+"/login/alpha")
	resp, _ = get(t, noRedirect, resp.Header.Get("Location")) // upstream authorize
	callbackURL := resp.Header.Get("Location")

	if resp, _ := get(t, noRedirect, callbackURL); resp.StatusCode != http.StatusFound {
		t.Fatalf("first callback should succeed, got %d", resp.StatusCode)
	}
	resp, body := get(t, noRedirect, callbackURL)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("replayed callback accepted: %d %s", resp.StatusCode, body)
	}
}

func TestTamperedStateRejected(t *testing.T) {
	e := newEnv(t)
	resp, _ := get(t, e.client(t), e.srv.URL+"/callback/alpha?state=forged.sig&code=x")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("forged state accepted: %d", resp.StatusCode)
	}
}

func TestEmailCollisionStaysUnlinked(t *testing.T) {
	e := newEnv(t)

	// Same email at two providers, different subjects: two identities.
	get(t, e.client(t), e.srv.URL+"/login/alpha")
	c := e.client(t)
	_, body := get(t, c, e.srv.URL+"/login/beta")

	idents, err := e.store.IdentitiesByEmail("alice@example.com")
	if err != nil || len(idents) != 2 {
		t.Fatalf("want 2 separate identities for colliding email, got %d (%v)", len(idents), err)
	}
	if !strings.Contains(body, "never merges") {
		t.Fatalf("account page should surface the collision and the no-merge rule:\n%s", body)
	}
}

func TestLinkingFlow(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)

	get(t, c, e.srv.URL+"/login/alpha")
	resp, err := c.Post(e.srv.URL+"/link/beta", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Request.URL.Path, "/account") {
		t.Fatalf("link flow: %d at %s: %s", resp.StatusCode, resp.Request.URL, body)
	}
	if !strings.Contains(string(body), "sub-a") || !strings.Contains(string(body), "sub-b") {
		t.Fatalf("account page missing one of the links:\n%s", body)
	}
	// Logging in via beta now resolves to the linked identity, not a new one.
	if _, err := e.store.IdentityByLink("beta", "sub-b"); err != nil {
		t.Fatalf("beta link not recorded: %v", err)
	}
	a, _ := e.store.IdentityByLink("alpha", "sub-a")
	b, _ := e.store.IdentityByLink("beta", "sub-b")
	if a.ID != b.ID {
		t.Fatalf("links resolve to different identities: %s vs %s", a.ID, b.ID)
	}
}

func TestLinkRequiresFreshAuth(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)

	get(t, c, e.srv.URL+"/login/alpha")
	e.clock.advance(10 * time.Minute) // past linkFreshness, session still alive

	resp, err := c.Post(e.srv.URL+"/link/beta", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("stale session allowed to start a link flow: %d %s", resp.StatusCode, body)
	}
	if len(mustLinks(t, e)) != 1 {
		t.Fatal("a link was added despite stale auth")
	}
}

func mustLinks(t *testing.T, e *env) []directory.Link {
	t.Helper()
	ident, err := e.store.IdentityByLink("alpha", "sub-a")
	if err != nil {
		t.Fatal(err)
	}
	links, err := e.store.Links(ident.ID)
	if err != nil {
		t.Fatal(err)
	}
	return links
}

func TestLinkingAlreadyLinkedAccountRejected(t *testing.T) {
	e := newEnv(t)

	get(t, e.client(t), e.srv.URL+"/login/beta") // beta's account gets its own identity
	c := e.client(t)
	get(t, c, e.srv.URL+"/login/alpha")
	resp, err := c.Post(e.srv.URL+"/link/beta", "", nil) // try to graft it on
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("linking an already-linked account should 409, got %d %s", resp.StatusCode, body)
	}
	if !strings.Contains(string(body), "never merges") {
		t.Fatalf("conflict page should state the no-merge rule:\n%s", body)
	}
}

func TestFailFastLoginPage(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	e.beta.SetFailing(true)

	// First attempt trips the breaker (threshold 1 in tests).
	resp, _ := get(t, c, e.srv.URL+"/login/beta")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("first failing attempt: %d", resp.StatusCode)
	}
	resp, body := get(t, c, e.srv.URL+"/login/beta")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("open breaker should fail fast with 503, got %d", resp.StatusCode)
	}
	if !strings.Contains(body, "/login/alpha") {
		t.Fatalf("fail-fast page must list healthy alternates:\n%s", body)
	}

	// Healthz reflects the open breaker.
	resp, hbody := get(t, c, e.srv.URL+"/healthz/providers")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("healthz with an open breaker: %d", resp.StatusCode)
	}
	var health struct {
		Providers []struct {
			Provider string `json:"provider"`
			State    string `json:"state"`
			Healthy  bool   `json:"healthy"`
		} `json:"providers"`
	}
	if err := json.Unmarshal([]byte(hbody), &health); err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, p := range health.Providers {
		states[p.Provider] = p.State
	}
	if states["alpha"] != "closed" || states["beta"] != "open" {
		t.Fatalf("breaker states: %v", states)
	}

	// Recovery: cooldown elapses, upstream healthy again, login works.
	e.beta.SetFailing(false)
	e.clock.advance(2 * time.Minute)
	resp, _ = get(t, c, e.srv.URL+"/login/beta")
	if resp.StatusCode != http.StatusOK || !strings.Contains(resp.Request.URL.Path, "/account") {
		t.Fatalf("post-recovery login: %d at %s", resp.StatusCode, resp.Request.URL)
	}
}

func TestLogout(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)

	get(t, c, e.srv.URL+"/login/alpha")
	resp, err := c.Post(e.srv.URL+"/logout", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, _ = get(t, c, e.srv.URL+"/account")
	if !strings.HasSuffix(resp.Request.URL.Path, "/") || resp.Request.URL.Path == "/account" {
		t.Fatalf("account after logout should bounce home, landed on %s", resp.Request.URL)
	}
}

func TestUnknownProviderAndApp(t *testing.T) {
	e := newEnv(t)
	c := e.client(t)
	if resp, _ := get(t, c, e.srv.URL+"/login/nope"); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown provider: %d", resp.StatusCode)
	}
	if resp, _ := get(t, c, e.srv.URL+"/login/alpha?app=evil"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("unregistered app: %d", resp.StatusCode)
	}
}

func TestUpstreamErrorParam(t *testing.T) {
	e := newEnv(t)
	resp, _ := get(t, e.client(t), e.srv.URL+"/callback/alpha?error=access_denied")
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("upstream error param: %d", resp.StatusCode)
	}
}
