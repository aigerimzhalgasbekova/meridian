package client

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aikazzh/portfolio/keysmith/jose"
	"github.com/aikazzh/portfolio/keysmith/keystore"
	"github.com/aikazzh/portfolio/keysmith/service"
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

type fixture struct {
	client  *Client
	manager *keystore.Manager
	clock   *clock
	// jwksHits counts JWKS endpoint requests (including 304s).
	jwksHits *atomic.Int64
}

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
	svc, err := service.New(manager, ksCfg, service.Config{
		SignerTokens: []string{"tok"},
		MaxTokenTTL:  time.Hour,
		JWKSMaxAge:   5 * time.Minute,
		Now:          ck.Now,
		Logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int64
	counting := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/jwks.json" {
			hits.Add(1)
		}
		svc.Handler().ServeHTTP(w, r)
	})
	srv := httptest.NewServer(counting)
	t.Cleanup(srv.Close)
	c := New(srv.URL, "tok", WithClock(ck.Now))
	return &fixture{client: c, manager: manager, clock: ck, jwksHits: &hits}
}

func TestClientSignAndVerify(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	token, err := f.client.Sign(ctx, SignRequest{
		Claims:     jose.Claims{Issuer: "https://idp.test", Subject: "alice"},
		TTLSeconds: 600,
	})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := f.client.Verify(ctx, token, jose.Expect{Issuer: "https://idp.test"})
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "alice" {
		t.Errorf("subject %q", claims.Subject)
	}
}

func TestClientCachesJWKS(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	token, err := f.client.Sign(ctx, SignRequest{Claims: jose.Claims{Subject: "a"}, TTLSeconds: 3000})
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		if _, err := f.client.Verify(ctx, token, jose.Expect{}); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.jwksHits.Load(); got != 1 {
		t.Errorf("JWKS fetched %d times for 10 verifies within max-age, want 1", got)
	}
	// Past max-age (from Cache-Control: 300s) the client revalidates.
	f.clock.Advance(6 * time.Minute)
	if _, err := f.client.Verify(ctx, token, jose.Expect{}); err != nil {
		t.Fatal(err)
	}
	if got := f.jwksHits.Load(); got != 2 {
		t.Errorf("JWKS hits after staleness: %d, want 2", got)
	}
}

func TestClientRefreshesOnUnknownKid(t *testing.T) {
	// A token signed by a key the client has never seen (post-rotation)
	// triggers exactly one forced refresh and then verifies.
	f := newFixture(t)
	ctx := context.Background()
	warm, err := f.client.Sign(ctx, SignRequest{Claims: jose.Claims{Subject: "a"}, TTLSeconds: 3000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.Verify(ctx, warm, jose.Expect{}); err != nil {
		t.Fatal(err) // cache is warm now
	}

	// Emergency rotation: new key signs immediately.
	k, err := f.manager.Generate(ctx, jose.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.manager.Promote(ctx, k.ID, true); err != nil {
		t.Fatal(err)
	}
	fresh, err := f.client.Sign(ctx, SignRequest{Claims: jose.Claims{Subject: "b"}, TTLSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := f.client.Verify(ctx, fresh, jose.Expect{})
	if err != nil {
		t.Fatalf("verify after rotation: %v", err)
	}
	if claims.Subject != "b" {
		t.Errorf("subject %q", claims.Subject)
	}
}

func TestClientServesStaleOnOutage(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	token, err := f.client.Sign(ctx, SignRequest{Claims: jose.Claims{Subject: "a"}, TTLSeconds: 3000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.Verify(ctx, token, jose.Expect{}); err != nil {
		t.Fatal(err)
	}
	// Keysmith goes down; cache is stale; verification must still work.
	f.clock.Advance(10 * time.Minute)
	f.client.baseURL = "http://127.0.0.1:1" // unroutable
	if _, err := f.client.Verify(ctx, token, jose.Expect{}); err != nil {
		t.Fatalf("stale-if-error failed: %v", err)
	}
}

func TestClientVerifyOnlyNoToken(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	token, err := f.client.Sign(ctx, SignRequest{Claims: jose.Claims{Subject: "a"}, TTLSeconds: 600})
	if err != nil {
		t.Fatal(err)
	}
	verifier := New(f.client.baseURL, "", WithClock(f.clock.Now))
	if _, err := verifier.Verify(ctx, token, jose.Expect{}); err != nil {
		t.Fatalf("verify-only client: %v", err)
	}
	// And signing without a token fails cleanly.
	if _, err := verifier.Sign(ctx, SignRequest{Claims: jose.Claims{Subject: "x"}, TTLSeconds: 60}); err == nil {
		t.Error("unauthenticated sign succeeded")
	}
}

func TestClientColdStartAgainstDeadServer(t *testing.T) {
	c := New("http://127.0.0.1:1", "")
	_, err := c.Verify(context.Background(), "x.y.z", jose.Expect{})
	if err == nil {
		t.Fatal("expected error with no keys ever fetched")
	}
	if errors.Is(err, jose.ErrSignatureInvalid) {
		t.Fatal("should fail on key fetch, not signature")
	}
}

// TestUnknownKidRefreshIsThrottled pins the amplification defense: jose
// reports ErrUnknownKey after only base64-decoding the token header, before
// any cryptography, so the kid is attacker-chosen. Without a bound, one bearer
// token per request is one JWKS fetch per request and a verifier under load
// becomes a load generator against the key server it depends on.
func TestUnknownKidRefreshIsThrottled(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	warm, err := f.client.Sign(ctx, SignRequest{Claims: jose.Claims{Subject: "a"}, TTLSeconds: 3000})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.client.Verify(ctx, warm, jose.Expect{}); err != nil {
		t.Fatal(err)
	}
	before := f.jwksHits.Load()

	// A token whose kid names a key that does not exist, 200 times over.
	forged := forgeUnknownKid(t, warm)
	for range 200 {
		if _, err := f.client.Verify(ctx, forged, jose.Expect{}); err == nil {
			t.Fatal("a token with an unknown kid must not verify")
		}
	}
	if got := f.jwksHits.Load() - before; got > 1 {
		t.Errorf("%d JWKS fetches for 200 unknown-kid verifies within the throttle window, want 1", got)
	}

	// Past the window a genuine rotation is still picked up promptly.
	f.clock.Advance(unknownKidInterval + time.Second)
	_, _ = f.client.Verify(ctx, forged, jose.Expect{})
	if got := f.jwksHits.Load() - before; got != 2 {
		t.Errorf("fetches after the window: %d, want 2 — the throttle must not wedge rotation", got)
	}
}

// forgeUnknownKid rewrites a token's header kid to one that does not exist.
func forgeUnknownKid(t *testing.T, token string) string {
	t.Helper()
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	hdr, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(hdr, &m); err != nil {
		t.Fatal(err)
	}
	m["kid"] = "no-such-key"
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(out) + "." + parts[1] + "." + parts[2]
}

// TestRefreshOnceContextIsolation pins the singleflight's two context rules:
// a waiter honours its own deadline instead of the leader's, and the shared
// fetch survives the leader going away. Verify runs on r.Context(), so binding
// the fetch to whoever arrived first would let one client disconnecting fail
// every other caller's perfectly valid token.
func TestRefreshOnceContextIsolation(t *testing.T) {
	hit := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit <- struct{}{}
		<-release
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"keys":[]}`)
	}))
	defer srv.Close()
	c := New(srv.URL, "")

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderErr := make(chan error, 1)
	go func() { _, err := c.refreshOnce(leaderCtx); leaderErr <- err }()
	<-hit // the fetch is in flight and parked in the handler

	// A waiter with a tight deadline must not inherit the leader's.
	waitCtx, cancelWait := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancelWait()
	start := time.Now()
	if _, err := c.refreshOnce(waitCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("impatient waiter got %v, want DeadlineExceeded", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("waiter blocked %v past its own deadline", d)
	}

	// The leader walks away mid-fetch; the callers still parked on the flight
	// it started must get the keys anyway.
	patient := make(chan error, 1)
	go func() { _, err := c.refreshOnce(context.Background()); patient <- err }()
	cancelLeader()
	if err := <-leaderErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader got %v, want Canceled", err)
	}
	close(release) // completes the in-flight fetch, and any the patient started
	if err := <-patient; err != nil {
		t.Fatalf("patient caller punished for the leader's cancellation: %v", err)
	}
}
