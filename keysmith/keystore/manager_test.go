package keystore

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/aikazzh/portfolio/keysmith/jose"
)

// fakeClock is a manually advanced clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func testConfig(clock *fakeClock, events *[]Event) Config {
	return Config{
		Algorithms:   []jose.Algorithm{jose.AlgEdDSA},
		PendingDwell: 10 * time.Minute,
		MaxKeyAge:    24 * time.Hour,
		RetireAfter:  time.Hour,
		Now:          clock.Now,
		Audit: func(e Event) {
			if events != nil {
				*events = append(*events, e)
			}
		},
	}
}

func statesByAlg(t *testing.T, m *Manager, alg jose.Algorithm) map[State]int {
	t.Helper()
	keys, err := m.Keys(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	out := map[State]int{}
	for _, k := range keys {
		if k.Alg == alg {
			out[k.State]++
		}
	}
	return out
}

func TestLifecycleZeroDowntimeRotation(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	var events []Event
	m, err := NewManager(NewMemoryStore(), testConfig(clock, &events))
	if err != nil {
		t.Fatal(err)
	}

	// Cold start: Tick bootstraps an active key immediately.
	if err := m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	sk1, err := m.SigningKey(ctx, jose.AlgEdDSA)
	if err != nil {
		t.Fatalf("no signing key after bootstrap: %v", err)
	}

	// Nothing to do while the key is fresh.
	clock.Advance(time.Hour)
	if err := m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if got := statesByAlg(t, m, jose.AlgEdDSA); got[StateActive] != 1 || got[StatePending] != 0 {
		t.Fatalf("unexpected states: %v", got)
	}

	// Approaching MaxKeyAge: a pending successor appears (pre-rotation)…
	clock.Advance(23 * time.Hour) // age now 24h ≥ 24h - 10m
	if err := m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	got := statesByAlg(t, m, jose.AlgEdDSA)
	if got[StatePending] != 1 || got[StateActive] != 1 {
		t.Fatalf("expected pending successor alongside active, got %v", got)
	}
	// …but signing still uses the old key: the successor must dwell first.
	skStill, err := m.SigningKey(ctx, jose.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if skStill.ID != sk1.ID {
		t.Fatal("signer changed before dwell elapsed — rotation is not zero-downtime")
	}
	// The successor is already published for verifiers to warm caches.
	jwks, err := m.JWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 2 {
		t.Fatalf("JWKS should carry active+pending, got %d keys", len(jwks.Keys))
	}

	// After the dwell: promoted; old key retiring but still published.
	clock.Advance(10 * time.Minute)
	if err := m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	sk2, err := m.SigningKey(ctx, jose.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if sk2.ID == sk1.ID {
		t.Fatal("signer did not rotate after dwell")
	}
	got = statesByAlg(t, m, jose.AlgEdDSA)
	if got[StateActive] != 1 || got[StateRetiring] != 1 {
		t.Fatalf("expected active+retiring, got %v", got)
	}
	// Tokens signed by the old key still verify during the retire window.
	set, err := m.VerificationSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.VerificationKey(sk1.ID); err != nil {
		t.Fatal("retiring key missing from verification set")
	}

	// After RetireAfter: the old key is unpublished.
	clock.Advance(time.Hour)
	if err := m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	set, err = m.VerificationSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.VerificationKey(sk1.ID); err == nil {
		t.Fatal("retired key still published")
	}
	got = statesByAlg(t, m, jose.AlgEdDSA)
	if got[StateRetired] != 1 {
		t.Fatalf("expected retired key, got %v", got)
	}

	// Audit trail captured every transition.
	ops := map[string]int{}
	for _, e := range events {
		ops[e.Op]++
	}
	if ops["generated"] != 2 || ops["promoted"] != 2 || ops["demoted"] != 1 || ops["retired"] != 1 {
		t.Errorf("audit ops: %v", ops)
	}
}

func TestPromoteEnforcesDwell(t *testing.T) {
	ctx := context.Background()
	clock := newFakeClock()
	m, err := NewManager(NewMemoryStore(), testConfig(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Tick(ctx); err != nil { // bootstrap active
		t.Fatal(err)
	}
	k, err := m.Generate(ctx, jose.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Promote(ctx, k.ID, false); !errors.Is(err, ErrDwellNotElapsed) {
		t.Fatalf("want ErrDwellNotElapsed, got %v", err)
	}
	// Force overrides (operator emergency path, e.g. key compromise).
	if err := m.Promote(ctx, k.ID, true); err != nil {
		t.Fatalf("forced promote: %v", err)
	}
	// A non-pending key cannot be promoted again.
	if err := m.Promote(ctx, k.ID, true); !errors.Is(err, ErrNotPending) {
		t.Fatalf("want ErrNotPending, got %v", err)
	}
}

func TestSigningAcrossRotationBoundary(t *testing.T) {
	// End-to-end: token signed before rotation verifies after rotation.
	ctx := context.Background()
	clock := newFakeClock()
	m, err := NewManager(NewMemoryStore(), testConfig(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	sk, err := m.SigningKey(ctx, jose.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jose.Sign([]byte(`{"sub":"alice"}`), sk)
	if err != nil {
		t.Fatal(err)
	}

	// Rotate fully: pre-rotate, dwell, promote.
	clock.Advance(24 * time.Hour)
	if err := m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	clock.Advance(10 * time.Minute)
	if err := m.Tick(ctx); err != nil {
		t.Fatal(err)
	}

	set, err := m.VerificationSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := jose.Verify(token, set, []jose.Algorithm{jose.AlgEdDSA}); err != nil {
		t.Fatalf("pre-rotation token failed to verify during retire window: %v", err)
	}

	// After the retire window the old token is no longer verifiable.
	clock.Advance(time.Hour)
	if err := m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	set, err = m.VerificationSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := jose.Verify(token, set, []jose.Algorithm{jose.AlgEdDSA}); err == nil {
		t.Fatal("token verifiable after its key retired")
	}
}

func TestConcurrentSigningDuringRotation(t *testing.T) {
	// Signing requests racing rotation must never observe "no active key".
	ctx := context.Background()
	clock := newFakeClock()
	m, err := NewManager(NewMemoryStore(), testConfig(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Tick(ctx); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	stop := make(chan struct{})
	errCh := make(chan error, 64)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				sk, err := m.SigningKey(ctx, jose.AlgEdDSA)
				if err != nil {
					errCh <- err
					return
				}
				if _, err := jose.Sign([]byte(`{}`), sk); err != nil {
					errCh <- err
					return
				}
			}
		}()
	}
	for range 50 {
		clock.Advance(30 * time.Minute)
		if err := m.Tick(ctx); err != nil {
			errCh <- err
			break
		}
	}
	close(stop)
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent signer: %v", err)
	}
}

// flakyStore fails the nth Update it sees, to model a full disk / EFS I/O
// error landing between promoteLocked's two non-transactional writes.
type flakyStore struct {
	*MemoryStore
	failUpdate int // 1-based index of the Update to fail; 0 disables
	updates    int
}

func (s *flakyStore) Update(ctx context.Context, k Key) error {
	s.updates++
	if s.failUpdate != 0 && s.updates == s.failUpdate {
		return errors.New("injected I/O error")
	}
	return s.MemoryStore.Update(ctx, k)
}

func TestPromoteRollsBackDemoteOnWriteFailure(t *testing.T) {
	// Promote demotes the incumbent and persists, then promotes the successor
	// and persists. If the second write fails, the committed demotion must not
	// be left standing: that leaves the algorithm with no active key at all —
	// every sign 503s until a Tick force-promotes, bypassing the dwell.
	ctx := context.Background()
	clock := newFakeClock()
	store := &flakyStore{MemoryStore: NewMemoryStore()}
	m, err := NewManager(store, testConfig(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Tick(ctx); err != nil { // bootstrap active
		t.Fatal(err)
	}
	k, err := m.Generate(ctx, jose.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(11 * time.Minute) // past the dwell

	store.updates, store.failUpdate = 0, 2 // fail the promote, not the demote
	if err := m.Promote(ctx, k.ID, false); err == nil {
		t.Fatal("Promote reported success despite a failed write")
	}
	store.failUpdate = 0

	if _, err := m.SigningKey(ctx, jose.AlgEdDSA); err != nil {
		t.Fatalf("no active key after a failed promotion: %v", err)
	}
	if got := statesByAlg(t, m, jose.AlgEdDSA); got[StateActive] != 1 || got[StateRetiring] != 0 {
		t.Fatalf("demotion was not rolled back: %v", got)
	}
}

func TestRevokeUnpublishesImmediatelyAndKeepsSigning(t *testing.T) {
	// The compromise response: force-promoting only stops the key signing new
	// *legitimate* tokens; an attacker holding the private half keeps minting,
	// and the key stays in the JWKS for the whole RetireAfter window. Revoke is
	// the only lever that closes that window.
	ctx := context.Background()
	clock := newFakeClock()
	var events []Event
	m, err := NewManager(NewMemoryStore(), testConfig(clock, &events))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	stolen, err := m.SigningKey(ctx, jose.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jose.Sign([]byte(`{"sub":"root"}`), stolen)
	if err != nil {
		t.Fatal(err)
	}

	if err := m.Revoke(ctx, stolen.ID, "private key leaked"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Unpublished now, not RetireAfter from now.
	set, err := m.VerificationSet(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := jose.Verify(token, set, []jose.Algorithm{jose.AlgEdDSA}); err == nil {
		t.Fatal("a token signed by the revoked key still verifies")
	}
	jwks, err := m.JWKS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range jwks.Keys {
		if j.Kid == stolen.ID {
			t.Fatal("revoked key is still published in the JWKS")
		}
	}

	// Containment, not an outage: a successor signs.
	successor, err := m.SigningKey(ctx, jose.AlgEdDSA)
	if err != nil {
		t.Fatalf("revoking the active key left no signer: %v", err)
	}
	if successor.ID == stolen.ID {
		t.Fatal("revoked key is still the signer")
	}
	var revoked int
	for _, e := range events {
		if e.Op == "revoked" && e.KeyID == stolen.ID && e.Detail["reason"] == "private key leaked" {
			revoked++
		}
	}
	if revoked != 1 {
		t.Errorf("audit trail has %d revoked events with the reason, want 1", revoked)
	}

	// Revoking twice is an error, not a silent no-op.
	if err := m.Revoke(ctx, stolen.ID, "again"); !errors.Is(err, ErrAlreadyRetired) {
		t.Errorf("want ErrAlreadyRetired, got %v", err)
	}
	if err := m.Revoke(ctx, "ghost", "x"); !errors.Is(err, ErrNotFound) {
		t.Errorf("want ErrNotFound, got %v", err)
	}
}

func TestRevokePrefersAWarmPendingSuccessor(t *testing.T) {
	// A pending key has already been published, so verifier caches know it —
	// preferring it over a fresh key is the difference between a seamless
	// containment and one that depends on every verifier's kid-miss refresh.
	ctx := context.Background()
	clock := newFakeClock()
	m, err := NewManager(NewMemoryStore(), testConfig(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	active, err := m.SigningKey(ctx, jose.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	warm, err := m.Generate(ctx, jose.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Revoke(ctx, active.ID, "compromise"); err != nil {
		t.Fatal(err)
	}
	sk, err := m.SigningKey(ctx, jose.AlgEdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if sk.ID != warm.ID {
		t.Errorf("signer is %q, want the pending key %q", sk.ID, warm.ID)
	}
}

func TestNewManagerValidation(t *testing.T) {
	store := NewMemoryStore()
	base := func() Config { return testConfig(newFakeClock(), nil) }

	cfg := base()
	cfg.Algorithms = nil
	if _, err := NewManager(store, cfg); err == nil {
		t.Error("no algorithms accepted")
	}
	cfg = base()
	cfg.PendingDwell = 25 * time.Hour // ≥ MaxKeyAge
	if _, err := NewManager(store, cfg); err == nil {
		t.Error("dwell ≥ MaxKeyAge accepted")
	}
	cfg = base()
	cfg.RSABits = 1024
	if _, err := NewManager(store, cfg); err == nil {
		t.Error("weak RSABits accepted")
	}
	cfg = base()
	cfg.Algorithms = []jose.Algorithm{"HS256"}
	if _, err := NewManager(store, cfg); err == nil {
		t.Error("HS256 accepted")
	}
}
