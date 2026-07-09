package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aikazzh/portfolio/sessiond/internal/store"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func testServer(t *testing.T, cfg Config) *httptest.Server {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	st := store.New(rdb, store.Config{CacheTTL: time.Millisecond, Logger: slog.New(slog.DiscardHandler)})
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	ts := httptest.NewServer(New(st, cfg).Handler())
	t.Cleanup(ts.Close)
	return ts
}

func doJSON(t *testing.T, method, url, token string, body any) *http.Response {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
	}
	req, err := http.NewRequest(method, url, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

func TestBearerAuth(t *testing.T) {
	ts := testServer(t, Config{APITokens: []string{"svc-token"}})

	tests := []struct {
		name  string
		token string
		want  int
	}{
		{"missing token", "", http.StatusUnauthorized},
		{"wrong token", "nope", http.StatusUnauthorized},
		{"valid token", "svc-token", http.StatusCreated},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			resp := doJSON(t, "POST", ts.URL+"/v1/sessions", tc.token,
				map[string]string{"realm": "acme", "user_id": "alice"})
			if resp.StatusCode != tc.want {
				t.Errorf("status = %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}

	// healthz needs no auth.
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("healthz = %d, want 200", resp.StatusCode)
	}
}

func TestAuthUnconfiguredFailsClosed(t *testing.T) {
	ts := testServer(t, Config{}) // no API tokens
	resp := doJSON(t, "POST", ts.URL+"/v1/sessions", "anything",
		map[string]string{"realm": "acme", "user_id": "alice"})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want 503 (fail closed, not open)", resp.StatusCode)
	}
}

func TestAPILifecycle(t *testing.T) {
	ts := testServer(t, Config{APITokens: []string{"svc"}})

	// Create.
	resp := doJSON(t, "POST", ts.URL+"/v1/sessions", "svc",
		map[string]string{"realm": "acme", "user_id": "alice", "ip": "203.0.113.7", "user_agent": "t/1"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create = %d", resp.StatusCode)
	}
	var created struct {
		Token   string        `json:"token"`
		Session store.Session `json:"session"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&created); err != nil {
		t.Fatal(err)
	}
	if created.Token == "" || created.Session.ID == "" {
		t.Fatalf("create response missing token or session: %+v", created)
	}

	// Validate + list.
	if r := doJSON(t, "POST", ts.URL+"/v1/sessions/validate", "svc",
		map[string]string{"token": created.Token}); r.StatusCode != http.StatusOK {
		t.Fatalf("validate = %d", r.StatusCode)
	}
	if r := doJSON(t, "GET", ts.URL+"/v1/users/acme/alice/sessions", "svc", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("list = %d", r.StatusCode)
	}

	// Rotate: old token dies, new one works.
	resp = doJSON(t, "POST", ts.URL+"/v1/sessions/rotate", "svc",
		map[string]string{"token": created.Token, "ip": "203.0.113.7", "user_agent": "t/1"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("rotate = %d", resp.StatusCode)
	}
	var rotated struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&rotated); err != nil {
		t.Fatal(err)
	}
	if r := doJSON(t, "POST", ts.URL+"/v1/sessions/validate", "svc",
		map[string]string{"token": created.Token}); r.StatusCode != http.StatusNotFound {
		t.Errorf("old token after rotate = %d, want 404", r.StatusCode)
	}

	// Revoke-all, then the rotated token is dead too.
	if r := doJSON(t, "DELETE", ts.URL+"/v1/users/acme/alice/sessions", "svc", nil); r.StatusCode != http.StatusOK {
		t.Fatalf("revoke-all = %d", r.StatusCode)
	}
	if r := doJSON(t, "POST", ts.URL+"/v1/sessions/validate", "svc",
		map[string]string{"token": rotated.Token}); r.StatusCode != http.StatusNotFound {
		t.Errorf("token after revoke-all = %d, want 404", r.StatusCode)
	}
}

func TestRevokeValidation(t *testing.T) {
	ts := testServer(t, Config{APITokens: []string{"svc"}})
	// Both or neither of token/id is a 400.
	for _, body := range []map[string]string{{}, {"token": "a", "id": "b"}} {
		if r := doJSON(t, "POST", ts.URL+"/v1/sessions/revoke", "svc", body); r.StatusCode != http.StatusBadRequest {
			t.Errorf("revoke %v = %d, want 400", body, r.StatusCode)
		}
	}
	// Revoking an unknown session is idempotent 204, not an oracle.
	if r := doJSON(t, "POST", ts.URL+"/v1/sessions/revoke", "svc",
		map[string]string{"token": "never-existed"}); r.StatusCode != http.StatusNoContent {
		t.Errorf("revoke unknown = %d, want 204", r.StatusCode)
	}
}

func TestDemoFlow(t *testing.T) {
	ts := testServer(t, Config{EnableDemo: true})
	client := ts.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // inspect redirects, don't follow
	}

	postForm := func(path string, form url.Values, cookie *http.Cookie) *http.Response {
		t.Helper()
		req, _ := http.NewRequest("POST", ts.URL+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { resp.Body.Close() })
		return resp
	}
	sessionCookie := func(resp *http.Response) *http.Cookie {
		t.Helper()
		for _, c := range resp.Cookies() {
			if c.Name == "meridian_session" {
				return c
			}
		}
		return nil
	}

	// Unauthenticated: redirected to login.
	resp, err := client.Get(ts.URL + "/demo/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/demo/login" {
		t.Fatalf("anon /demo/ = %d -> %q, want 303 -> /demo/login", resp.StatusCode, resp.Header.Get("Location"))
	}

	// Bad credentials: no cookie set.
	resp = postForm("/demo/login", url.Values{"username": {"alice"}, "password": {"wrong"}}, nil)
	if resp.StatusCode != http.StatusOK || sessionCookie(resp) != nil {
		t.Fatalf("bad login: status %d, cookie %v", resp.StatusCode, sessionCookie(resp))
	}

	// Good credentials: session cookie, protected page renders.
	resp = postForm("/demo/login", url.Values{"username": {"alice"}, "password": {"wonderland"}}, nil)
	ck := sessionCookie(resp)
	if resp.StatusCode != http.StatusSeeOther || ck == nil || ck.Value == "" {
		t.Fatalf("login: status %d, cookie %v", resp.StatusCode, ck)
	}
	if !ck.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
	req, _ := http.NewRequest("GET", ts.URL+"/demo/", nil)
	req.AddCookie(ck)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("protected page = %d, want 200", resp.StatusCode)
	}

	// Log out everywhere: cookie cleared and old session dead.
	resp = postForm("/demo/logout-all", nil, ck)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout-all = %d", resp.StatusCode)
	}
	if cleared := sessionCookie(resp); cleared == nil || cleared.MaxAge >= 0 {
		t.Errorf("logout-all should clear cookie, got %v", cleared)
	}
	req, _ = http.NewRequest("GET", ts.URL+"/demo/", nil)
	req.AddCookie(ck)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("old cookie after logout-all = %d, want redirect to login", resp.StatusCode)
	}
}

func TestDemoDisabledByDefault(t *testing.T) {
	ts := testServer(t, Config{APITokens: []string{"svc"}})
	resp, err := http.Get(fmt.Sprintf("%s/demo/login", ts.URL))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("demo without EnableDemo = %d, want 404", resp.StatusCode)
	}
}
