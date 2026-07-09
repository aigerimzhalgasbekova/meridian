package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aikazzh/portfolio/keysmith/jose"
	"github.com/aikazzh/portfolio/keysmith/keystore"
)

type fixture struct {
	srv     *httptest.Server
	manager *keystore.Manager
	clock   *clock
}

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

const (
	signerToken = "signer-secret"
	adminToken  = "admin-secret"
)

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ck := &clock{t: time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)}
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
	s, err := New(manager, ksCfg, Config{
		SignerTokens: []string{signerToken},
		AdminTokens:  []string{adminToken},
		MaxTokenTTL:  time.Hour,
		JWKSMaxAge:   5 * time.Minute,
		Now:          ck.Now,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &fixture{srv: srv, manager: manager, clock: ck}
}

func (f *fixture) do(t *testing.T, method, path, token string, body any) (*http.Response, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, f.srv.URL+path, rd)
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
	raw, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return resp, raw
}

func signBody(claims map[string]any, ttl int64) map[string]any {
	return map[string]any{"claims": claims, "ttl_seconds": ttl}
}

func TestSignVerifyEndToEnd(t *testing.T) {
	f := newFixture(t)
	resp, raw := f.do(t, "POST", "/v1/sign", signerToken,
		signBody(map[string]any{"sub": "alice", "iss": "https://idp.test"}, 600))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign: %s: %s", resp.Status, raw)
	}
	var signed struct {
		Token string `json:"token"`
		Kid   string `json:"kid"`
		Exp   int64  `json:"exp"`
	}
	if err := json.Unmarshal(raw, &signed); err != nil {
		t.Fatal(err)
	}
	if signed.Exp != f.clock.Now().Add(10*time.Minute).Unix() {
		t.Errorf("exp = %d, want now+600s", signed.Exp)
	}

	resp, raw = f.do(t, "POST", "/v1/verify", signerToken,
		map[string]any{"token": signed.Token, "issuer": "https://idp.test"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify: %s: %s", resp.Status, raw)
	}
	var verified struct {
		Valid  bool           `json:"valid"`
		Claims map[string]any `json:"claims"`
	}
	if err := json.Unmarshal(raw, &verified); err != nil {
		t.Fatal(err)
	}
	if !verified.Valid || verified.Claims["sub"] != "alice" {
		t.Errorf("verify result: %s", raw)
	}

	// Expiry: advance past exp, coarse reason only.
	f.clock.Advance(11 * time.Minute)
	resp, raw = f.do(t, "POST", "/v1/verify", signerToken, map[string]any{"token": signed.Token})
	var expired struct {
		Valid  bool   `json:"valid"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(raw, &expired); err != nil {
		t.Fatal(err)
	}
	if expired.Valid || expired.Reason != "expired" {
		t.Errorf("expired verify: %s", raw)
	}
}

func TestSignValidation(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name string
		body map[string]any
		want int
	}{
		{"missing claims", map[string]any{"ttl_seconds": 60}, http.StatusBadRequest},
		{"zero ttl", signBody(map[string]any{"sub": "x"}, 0), http.StatusBadRequest},
		{"ttl exceeds max", signBody(map[string]any{"sub": "x"}, 7200), http.StatusBadRequest},
		{"client-supplied exp", map[string]any{
			"claims": map[string]any{"sub": "x", "exp": 9999999999}, "ttl_seconds": 60,
		}, http.StatusBadRequest},
		{"unsupported alg", map[string]any{
			"claims": map[string]any{"sub": "x"}, "ttl_seconds": 60, "alg": "HS256",
		}, http.StatusBadRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, raw := f.do(t, "POST", "/v1/sign", signerToken, tc.body)
			if resp.StatusCode != tc.want {
				t.Errorf("status %d, want %d: %s", resp.StatusCode, tc.want, raw)
			}
		})
	}
}

func TestAuthBoundaries(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name, method, path, token string
		want                      int
	}{
		{"jwks is public", "GET", "/.well-known/jwks.json", "", http.StatusOK},
		{"health is public", "GET", "/healthz", "", http.StatusOK},
		{"sign requires token", "POST", "/v1/sign", "", http.StatusUnauthorized},
		{"sign rejects wrong token", "POST", "/v1/sign", "wrong", http.StatusUnauthorized},
		{"sign rejects admin token", "POST", "/v1/sign", adminToken, http.StatusUnauthorized},
		{"keys requires admin", "GET", "/v1/keys", "", http.StatusUnauthorized},
		{"keys rejects signer token", "GET", "/v1/keys", signerToken, http.StatusUnauthorized},
		{"keys with admin", "GET", "/v1/keys", adminToken, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var body any
			if tc.method == "POST" {
				body = signBody(map[string]any{"sub": "x"}, 60)
			}
			resp, _ := f.do(t, tc.method, tc.path, tc.token, body)
			if resp.StatusCode != tc.want {
				t.Errorf("status %d, want %d", resp.StatusCode, tc.want)
			}
		})
	}
}

func TestKeyListNeverLeaksPrivateMaterial(t *testing.T) {
	f := newFixture(t)
	_, raw := f.do(t, "GET", "/v1/keys", adminToken, nil)
	for _, banned := range []string{"private", "\"d\":", "seed"} {
		if strings.Contains(strings.ToLower(string(raw)), banned) {
			t.Errorf("key list contains %q: %s", banned, raw)
		}
	}
	_, raw = f.do(t, "GET", "/.well-known/jwks.json", "", nil)
	if strings.Contains(string(raw), "\"d\":") {
		t.Errorf("JWKS contains private component: %s", raw)
	}
}

func TestJWKSCachingHeaders(t *testing.T) {
	f := newFixture(t)
	resp, _ := f.do(t, "GET", "/.well-known/jwks.json", "", nil)
	if cc := resp.Header.Get("Cache-Control"); cc != "public, max-age=300" {
		t.Errorf("Cache-Control: %q", cc)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		t.Fatal("no ETag")
	}
	req, _ := http.NewRequest("GET", f.srv.URL+"/.well-known/jwks.json", nil)
	req.Header.Set("If-None-Match", etag)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotModified {
		t.Errorf("If-None-Match: got %d, want 304", resp2.StatusCode)
	}

	// Rotation changes the document and must change the ETag.
	if _, err := f.manager.Generate(context.Background(), jose.AlgEdDSA); err != nil {
		t.Fatal(err)
	}
	resp3, _ := f.do(t, "GET", "/.well-known/jwks.json", "", nil)
	if resp3.Header.Get("ETag") == etag {
		t.Error("ETag unchanged after key generation")
	}
}

func TestAdminRotationFlow(t *testing.T) {
	f := newFixture(t)
	resp, raw := f.do(t, "POST", "/v1/keys/generate", adminToken, map[string]any{"alg": "EdDSA"})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("generate: %s: %s", resp.Status, raw)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatal(err)
	}

	// Promote before dwell → 409.
	resp, raw = f.do(t, "POST", fmt.Sprintf("/v1/keys/%s/promote", created.ID), adminToken, nil)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("early promote: %d: %s", resp.StatusCode, raw)
	}
	// Force promote → 200.
	resp, raw = f.do(t, "POST", fmt.Sprintf("/v1/keys/%s/promote", created.ID), adminToken,
		map[string]any{"force": true})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("force promote: %d: %s", resp.StatusCode, raw)
	}
	// Unknown key → 404.
	resp, _ = f.do(t, "POST", "/v1/keys/ghost/promote", adminToken, nil)
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("ghost promote: %d, want 404", resp.StatusCode)
	}
}

func TestServiceConfigCrossValidation(t *testing.T) {
	ksCfg := keystore.Config{
		Algorithms:   []jose.Algorithm{jose.AlgEdDSA},
		PendingDwell: 10 * time.Minute,
		MaxKeyAge:    24 * time.Hour,
		RetireAfter:  time.Hour,
	}
	manager, err := keystore.NewManager(keystore.NewMemoryStore(), ksCfg)
	if err != nil {
		t.Fatal(err)
	}
	// Token TTL beyond RetireAfter would strand live tokens on rotation.
	if _, err := New(manager, ksCfg, Config{MaxTokenTTL: 2 * time.Hour}); err == nil {
		t.Error("MaxTokenTTL > RetireAfter accepted")
	}
	// JWKS cache longer than half the dwell defeats pre-publication.
	if _, err := New(manager, ksCfg, Config{JWKSMaxAge: 6 * time.Minute}); err == nil {
		t.Error("JWKSMaxAge > PendingDwell/2 accepted")
	}
}
