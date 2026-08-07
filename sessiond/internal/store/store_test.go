package store

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// fakeClock is advanced in lockstep with miniredis.FastForward so that both
// the store's expiry decisions (deadline checks) and Redis TTLs move together.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock { return &fakeClock{t: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

// advance moves the clock only (simulates skew or cache aging without TTLs moving).
func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// tick moves the clock and Redis TTLs together (normal passage of time).
func (c *fakeClock) tick(mr *miniredis.Miniredis, d time.Duration) {
	c.advance(d)
	mr.FastForward(d)
}

func testStore(t *testing.T, mr *miniredis.Miniredis, clk *fakeClock, cfg Config) *Store {
	t.Helper()
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { rdb.Close() })
	cfg.Now = clk.Now
	cfg.Logger = slog.New(slog.DiscardHandler)
	return New(rdb, cfg)
}

func mustCreate(t *testing.T, s *Store, realm, uid string) (string, Session) {
	t.Helper()
	tok, sess, err := s.Create(context.Background(), realm, uid, "203.0.113.7", "test-agent/1.0")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return tok, sess
}

func TestCreateValidate(t *testing.T) {
	mr := miniredis.RunT(t)
	clk := newFakeClock()
	s := testStore(t, mr, clk, Config{})
	ctx := context.Background()

	tok, created := mustCreate(t, s, "acme", "alice")

	got, err := s.Validate(ctx, tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.ID != created.ID || got.UserID != "alice" || got.Realm != "acme" {
		t.Errorf("session mismatch: got %+v want %+v", got, created)
	}
	if got.UAHash == "" || got.UAHash == "test-agent/1.0" {
		t.Errorf("user agent must be stored as a fingerprint, got %q", got.UAHash)
	}
	if !got.AbsDeadline.Equal(created.CreatedAt.Add(12 * time.Hour)) {
		t.Errorf("deadline = %v, want created+12h", got.AbsDeadline)
	}

	// Redis must hold only the token hash, never the token.
	if mr.Exists("sess:" + tok) {
		t.Error("raw token used as a Redis key")
	}
	if !mr.Exists("sess:" + created.ID) {
		t.Error("session not stored under its SHA-256 ID")
	}

	if _, err := s.Validate(ctx, "no-such-token"); !errors.Is(err, ErrNotFound) {
		t.Errorf("unknown token: got %v, want ErrNotFound", err)
	}
}

func TestBadNamesRejected(t *testing.T) {
	mr := miniredis.RunT(t)
	s := testStore(t, mr, newFakeClock(), Config{})
	ctx := context.Background()
	for _, bad := range []string{"", "a:b", "x y", "u\n"} {
		if _, _, err := s.Create(ctx, bad, "alice", "", ""); !errors.Is(err, ErrBadName) {
			t.Errorf("Create realm %q: got %v, want ErrBadName", bad, err)
		}
		if _, err := s.List(ctx, "acme", bad); !errors.Is(err, ErrBadName) {
			t.Errorf("List uid %q: got %v, want ErrBadName", bad, err)
		}
	}
}

func TestSlidingExpiry(t *testing.T) {
	mr := miniredis.RunT(t)
	clk := newFakeClock()
	// Cache off (1ms) so every Validate hits Redis and actually touches.
	s := testStore(t, mr, clk, Config{IdleTTL: 10 * time.Minute, AbsoluteTTL: time.Hour, CacheTTL: time.Millisecond})
	ctx := context.Background()

	tok, _ := mustCreate(t, s, "acme", "alice")

	// Touch every 8m: each touch renews the 10m idle window.
	for i := 0; i < 3; i++ {
		clk.tick(mr, 8*time.Minute)
		if _, err := s.Validate(ctx, tok); err != nil {
			t.Fatalf("validate after %dm idle: %v", 8*(i+1), err)
		}
	}

	// Go idle past the window: dead.
	clk.tick(mr, 11*time.Minute)
	if _, err := s.Validate(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after idle timeout: got %v, want ErrNotFound", err)
	}
}

func TestAbsoluteCapNotExtendedByTouches(t *testing.T) {
	mr := miniredis.RunT(t)
	clk := newFakeClock()
	s := testStore(t, mr, clk, Config{IdleTTL: 10 * time.Minute, AbsoluteTTL: 30 * time.Minute, CacheTTL: time.Millisecond})
	ctx := context.Background()

	tok, _ := mustCreate(t, s, "acme", "alice")

	// Touch diligently every 5m — the session must still die at 30m.
	for i := 0; i < 5; i++ { // t = 5..25m
		clk.tick(mr, 5*time.Minute)
		if _, err := s.Validate(ctx, tok); err != nil {
			t.Fatalf("validate at t=%dm: %v", 5*(i+1), err)
		}
	}
	clk.tick(mr, 6*time.Minute) // t = 31m > 30m cap, but only 6m idle
	if _, err := s.Validate(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Fatalf("past absolute cap: got %v, want ErrNotFound", err)
	}
}

func TestDeadlineCheckedEvenIfTTLStale(t *testing.T) {
	// The Redis key TTL may lag reality (clock skew, restored snapshot).
	// Advance only the store's clock: the key still exists in miniredis, but
	// the touch script's deadline check must refuse it.
	mr := miniredis.RunT(t)
	clk := newFakeClock()
	s := testStore(t, mr, clk, Config{IdleTTL: 10 * time.Minute, AbsoluteTTL: 30 * time.Minute, CacheTTL: time.Millisecond})
	ctx := context.Background()

	tok, sess := mustCreate(t, s, "acme", "alice")
	clk.advance(31 * time.Minute) // clock moves, TTLs do not
	if !mr.Exists("sess:" + sess.ID) {
		t.Fatal("precondition: key should still exist in redis")
	}
	if _, err := s.Validate(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Fatalf("stale-TTL session past deadline: got %v, want ErrNotFound", err)
	}
	if mr.Exists("sess:" + sess.ID) {
		t.Error("expired session should be deleted by the touch script")
	}
}

func TestConcurrentLimitEvictOldest(t *testing.T) {
	mr := miniredis.RunT(t)
	clk := newFakeClock()
	s := testStore(t, mr, clk, Config{MaxPerUser: 3, CacheTTL: time.Millisecond})
	ctx := context.Background()

	var toks []string
	for i := 0; i < 4; i++ {
		tok, _ := mustCreate(t, s, "acme", "alice")
		toks = append(toks, tok)
		clk.tick(mr, time.Second) // distinct creation times
	}

	// Oldest evicted, rest alive.
	if _, err := s.Validate(ctx, toks[0]); !errors.Is(err, ErrNotFound) {
		t.Errorf("oldest session: got %v, want ErrNotFound (evicted)", err)
	}
	for i, tok := range toks[1:] {
		if _, err := s.Validate(ctx, tok); err != nil {
			t.Errorf("session %d: %v", i+1, err)
		}
	}
	sessions, err := s.List(ctx, "acme", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 3 {
		t.Errorf("live sessions = %d, want 3", len(sessions))
	}
	// Oldest-first ordering.
	for i := 1; i < len(sessions); i++ {
		if sessions[i].CreatedAt.Before(sessions[i-1].CreatedAt) {
			t.Error("List not ordered oldest-first")
		}
	}
}

func TestConcurrentLimitReject(t *testing.T) {
	mr := miniredis.RunT(t)
	clk := newFakeClock()
	s := testStore(t, mr, clk, Config{MaxPerUser: 2, Policy: Reject, CacheTTL: time.Millisecond})
	ctx := context.Background()

	tok1, _ := mustCreate(t, s, "acme", "alice")
	mustCreate(t, s, "acme", "alice")
	if _, _, err := s.Create(ctx, "acme", "alice", "", ""); !errors.Is(err, ErrSessionLimit) {
		t.Fatalf("over cap: got %v, want ErrSessionLimit", err)
	}
	// Existing sessions untouched by the rejected attempt.
	if _, err := s.Validate(ctx, tok1); err != nil {
		t.Errorf("existing session after reject: %v", err)
	}
	// Expired sessions must not count against the cap.
	clk.tick(mr, 31*time.Minute) // default IdleTTL 30m
	if _, _, err := s.Create(ctx, "acme", "alice", "", ""); err != nil {
		t.Errorf("create after old sessions expired: %v", err)
	}
}

func TestRotate(t *testing.T) {
	mr := miniredis.RunT(t)
	clk := newFakeClock()
	s := testStore(t, mr, clk, Config{AbsoluteTTL: time.Hour, CacheTTL: time.Millisecond})
	ctx := context.Background()

	oldTok, oldSess := mustCreate(t, s, "acme", "alice")
	clk.tick(mr, 5*time.Minute)

	newTok, newSess, err := s.Rotate(ctx, oldTok, "198.51.100.9", "elevated-agent/2.0")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if newTok == oldTok || newSess.ID == oldSess.ID {
		t.Fatal("rotation must mint a new token and ID")
	}
	// Old identity dead, atomically.
	if _, err := s.Validate(ctx, oldTok); !errors.Is(err, ErrNotFound) {
		t.Errorf("old token after rotate: got %v, want ErrNotFound", err)
	}
	// New identity live, lifetime NOT extended.
	got, err := s.Validate(ctx, newTok)
	if err != nil {
		t.Fatalf("new token: %v", err)
	}
	if !got.CreatedAt.Equal(oldSess.CreatedAt) {
		t.Errorf("CreatedAt = %v, want carried over %v", got.CreatedAt, oldSess.CreatedAt)
	}
	if !got.AbsDeadline.Equal(oldSess.AbsDeadline) {
		t.Errorf("rotation extended absolute deadline: %v -> %v", oldSess.AbsDeadline, got.AbsDeadline)
	}
	// Exactly one session in the index.
	sessions, _ := s.List(ctx, "acme", "alice")
	if len(sessions) != 1 || sessions[0].ID != newSess.ID {
		t.Errorf("index after rotate: %+v", sessions)
	}
	// Rotating a user's only session empties the ZSET, so Redis deletes it —
	// TTL and all — and the re-ADD must not leave an immortal key behind.
	if ttl := mr.TTL("usersess:acme:alice:sessions"); ttl <= 0 {
		t.Errorf("index TTL after rotate = %v, want > 0 (leaked persistent key)", ttl)
	}

	// Rotating a dead token fails closed.
	if _, _, err := s.Rotate(ctx, oldTok, "", ""); !errors.Is(err, ErrNotFound) {
		t.Errorf("rotate dead token: got %v, want ErrNotFound", err)
	}
}

// TestIndexOutlivesLongerLivedSessions pins the invariant the whole index
// rests on: `usersess:...` must never expire before the longest-lived session
// it holds. Lowering SESSIOND_ABSOLUTE_TTL (a routine security tightening, and
// transiently the state of any rolling deploy) used to rewrite the index TTL
// downwards, orphaning live sessions from revoke-all, List and the cap.
func TestIndexOutlivesLongerLivedSessions(t *testing.T) {
	mr := miniredis.RunT(t)
	clk := newFakeClock()
	ctx := context.Background()
	const indexKey = "usersess:acme:alice:sessions"

	long := testStore(t, mr, clk, Config{AbsoluteTTL: 12 * time.Hour, CacheTTL: time.Millisecond})
	tok1, _ := mustCreate(t, long, "acme", "alice")
	clk.tick(mr, time.Minute)

	// A node that has picked up a reduced AbsoluteTTL creates a second session.
	short := testStore(t, mr, clk, Config{AbsoluteTTL: time.Hour, CacheTTL: time.Millisecond})
	mustCreate(t, short, "acme", "alice")
	if ttl := mr.TTL(indexKey); ttl < 11*time.Hour {
		t.Fatalf("index TTL = %v, want ≥ the 12h session's remaining life", ttl)
	}

	// Well past the short node's TTL, with session 1 kept active the way a
	// real user would keep it alive.
	for i := 0; i < 5; i++ {
		clk.tick(mr, 20*time.Minute)
		if _, err := long.Validate(ctx, tok1); err != nil {
			t.Fatalf("session 1 at t=%dm: %v", 20*(i+1), err)
		}
	}

	if _, err := long.RevokeUser(ctx, "acme", "alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := long.Validate(ctx, tok1); !errors.Is(err, ErrNotFound) {
		t.Errorf("session survived revoke-all: got %v, want ErrNotFound", err)
	}
}

// TestIndexSurvivesBackwardClockStep is the same invariant reached without any
// config change: touch restretches the session key from the node's clock, so a
// node whose clock steps backward (NTP correction, drifting VM) keeps the key
// alive past an index TTL that was frozen in Redis-real time at create. The
// orphaned session used to survive revoke-all silently.
func TestIndexSurvivesBackwardClockStep(t *testing.T) {
	mr := miniredis.RunT(t)
	clk := newFakeClock()
	s := testStore(t, mr, clk, Config{AbsoluteTTL: 2 * time.Hour, CacheTTL: time.Millisecond})
	ctx := context.Background()

	tok, _ := mustCreate(t, s, "acme", "alice")
	clk.advance(-time.Hour) // NTP steps this node's clock back an hour

	// Two hours of real time pass while the user keeps the session active.
	for i := 0; i < 6; i++ {
		clk.tick(mr, 20*time.Minute)
		if _, err := s.Validate(ctx, tok); err != nil {
			t.Fatalf("session at t=%dm: %v", 20*(i+1), err)
		}
	}

	n, err := s.RevokeUser(ctx, "acme", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("RevokeUser revoked %d, want 1 (session orphaned from its index)", n)
	}
	if _, err := s.Validate(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Errorf("session survived revoke-all: got %v, want ErrNotFound", err)
	}
}

// TestListSkipsSessionsPastDeadline is TestDeadlineCheckedEvenIfTTLStale for
// the admin listing surface: List must agree with Validate about what is live.
func TestListSkipsSessionsPastDeadline(t *testing.T) {
	mr := miniredis.RunT(t)
	clk := newFakeClock()
	s := testStore(t, mr, clk, Config{IdleTTL: 10 * time.Minute, AbsoluteTTL: 30 * time.Minute, CacheTTL: time.Millisecond})
	ctx := context.Background()

	_, sess := mustCreate(t, s, "acme", "alice")
	clk.advance(31 * time.Minute) // clock moves, TTLs do not

	sessions, err := s.List(ctx, "acme", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 0 {
		t.Errorf("List returned %d past-deadline sessions, want 0", len(sessions))
	}
	// Refusing to report is the whole job: List is a read on an unvalidated
	// clock, so it must not destroy the record. touchScript does that, on the
	// node that actually serves the session.
	if !mr.Exists("sess:" + sess.ID) {
		t.Error("List destroyed a session it should only have hidden")
	}
}

// TestListDoesNotDeleteOnClockSkew is the fleet-level version: one node running
// fast must not be able to kill sessions that are live everywhere else, and a
// GET must not be a destructive write.
func TestListDoesNotDeleteOnClockSkew(t *testing.T) {
	mr := miniredis.RunT(t)
	good := newFakeClock()
	cfg := Config{IdleTTL: 10 * time.Minute, AbsoluteTTL: 30 * time.Minute, CacheTTL: time.Millisecond}
	s := testStore(t, mr, good, cfg)
	ctx := context.Background()

	tok, _ := mustCreate(t, s, "acme", "alice")

	// A second node whose clock is 2h fast renders the admin listing.
	fast := newFakeClock()
	fast.advance(2 * time.Hour)
	if _, err := testStore(t, mr, fast, cfg).List(ctx, "acme", "alice"); err != nil {
		t.Fatal(err)
	}

	// The session is still well inside its deadline on a correct clock.
	if _, err := s.Validate(ctx, tok); err != nil {
		t.Fatalf("session killed by a fast node's listing: %v", err)
	}
	sessions, err := s.List(ctx, "acme", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Errorf("live sessions after a skewed listing = %d, want 1", len(sessions))
	}
}

// TestCacheExpiryMeasuredFromReadTime pins the documented bound: an entry may
// outlive the Redis read it describes by CacheTTL, not by CacheTTL plus
// however long the round trip took.
func TestCacheExpiryMeasuredFromReadTime(t *testing.T) {
	clk := newFakeClock()
	c := newCache(2*time.Second, clk.Now)

	readAt := clk.Now().UnixMilli()
	clk.advance(3 * time.Second) // a degraded Redis: the reply lands 3s late
	c.put("id", Session{ID: "id"}, readAt)

	if _, _, ok := c.get("id"); ok {
		t.Error("entry filled from a 3s-old read must already be expired")
	}
}

// TestValidateTolerantOfPartialRecord: a session hash missing realm/uid (a
// partial restore, an operator's HDEL) must still validate — the index upkeep
// touchScript does is best-effort, not a precondition. Concatenating a missing
// field in Lua raises, which would turn such a record into a permanent 500.
func TestValidateTolerantOfPartialRecord(t *testing.T) {
	mr := miniredis.RunT(t)
	clk := newFakeClock()
	s := testStore(t, mr, clk, Config{CacheTTL: time.Millisecond})
	ctx := context.Background()

	tok, sess := mustCreate(t, s, "acme", "alice")
	mr.HDel("sess:"+sess.ID, "realm")
	mr.HDel("sess:"+sess.ID, "uid")

	got, err := s.Validate(ctx, tok)
	if err != nil {
		t.Fatalf("Validate on a partial record: %v", err)
	}
	if got.ID != sess.ID {
		t.Errorf("session id = %q, want %q", got.ID, sess.ID)
	}
}

func TestRevokeAndRevokeUser(t *testing.T) {
	mr := miniredis.RunT(t)
	clk := newFakeClock()
	s := testStore(t, mr, clk, Config{CacheTTL: time.Millisecond})
	ctx := context.Background()

	tok1, _ := mustCreate(t, s, "acme", "alice")
	tok2, _ := mustCreate(t, s, "acme", "alice")
	tok3, _ := mustCreate(t, s, "acme", "bob")

	if err := s.RevokeToken(ctx, tok1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Validate(ctx, tok1); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoked token: got %v", err)
	}
	if err := s.RevokeToken(ctx, tok1); err != nil {
		t.Errorf("revoke is not idempotent: %v", err)
	}

	n, err := s.RevokeUser(ctx, "acme", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("RevokeUser revoked %d, want 1", n)
	}
	if _, err := s.Validate(ctx, tok2); !errors.Is(err, ErrNotFound) {
		t.Errorf("alice's session after revoke-all: got %v", err)
	}
	// Bob unaffected.
	if _, err := s.Validate(ctx, tok3); err != nil {
		t.Errorf("bob's session: %v", err)
	}
}
