//go:build integration

// Integration tests for the session store against a real Redis. Run with:
//
//	TEST_REDIS_URL=redis://localhost:6379/1 go test -tags integration ./internal/store/
//
// Every other test in this package runs on miniredis, a Go reimplementation.
// miniredis is a better fake than it gets credit for: it applies each command
// under a lock exactly as single-threaded Redis does, so a check-and-act split
// across separate round trips races there too, and the concurrency tests in
// concurrency_test.go do catch it. Atomicity is not the gap.
//
// The gap is everything about Redis that miniredis reimplements rather than
// runs:
//
//   - Its Lua is gopher-lua, not the Lua 5.1 embedded in Redis. Number
//     formatting, tostring(), tonumber(), and reply conversion are the
//     interpreter's, not Redis's. A script can mean one thing under test and
//     another in production.
//   - Its TTLs advance by FastForward, never by a clock. That proves the
//     store's expiry algebra and not that the PEXPIRE we issue carries the
//     value we think it does.
//   - Its pub/sub is in-process channels, so the revocation broadcast is never
//     serialized, published, or delivered over a connection.
//
// Note what is NOT on that list: miniredis implements EVAL, EVALSHA and
// SCRIPT, so the scripts do load and run under it. Only their meaning is in
// question, never their execution.
//
// So this file runs the scripts on Redis and re-checks only what changes when
// the interpreter, the clock, and the wire are real. It deliberately does not
// re-test the fake-clock expiry algebra or the cache staleness bounds, which
// miniredis already covers well and faster.
//
// The suite FLUSHDBs before each test: point TEST_REDIS_URL at a throwaway
// database, never a shared one.
package store

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

func redisURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("TEST_REDIS_URL")
	if url == "" {
		// CI's integration job sets REQUIRE_TEST_REDIS_URL. Skipping is the
		// right default locally, but a suite that skips when Redis disappears
		// stops protecting anything without ever going red.
		if os.Getenv("REQUIRE_TEST_REDIS_URL") != "" {
			t.Fatal("REQUIRE_TEST_REDIS_URL is set but TEST_REDIS_URL is empty")
		}
		t.Skip("TEST_REDIS_URL not set")
	}
	return url
}

func dial(t *testing.T, url string) *redis.Client {
	t.Helper()
	opts, err := redis.ParseURL(url)
	if err != nil {
		t.Fatalf("TEST_REDIS_URL: %v", err)
	}
	rdb := redis.NewClient(opts)
	t.Cleanup(func() { rdb.Close() })
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		t.Fatalf("redis ping: %v", err)
	}
	return rdb
}

// testRedis returns a client on a freshly flushed database, plus the URL so a
// test can dial a second connection to stand in for a second node.
func testRedis(t *testing.T) (string, *redis.Client) {
	t.Helper()
	url := redisURL(t)
	rdb := dial(t, url)
	if err := rdb.FlushDB(context.Background()).Err(); err != nil {
		t.Fatalf("flushdb: %v", err)
	}
	return url, rdb
}

// realStore builds a Store on a real Redis. CacheTTL defaults to ~nothing so
// every Validate reaches Redis; tests about caching set it explicitly.
func realStore(t *testing.T, rdb redis.UniversalClient, cfg Config) *Store {
	t.Helper()
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = time.Millisecond
	}
	cfg.Logger = slog.New(slog.DiscardHandler)
	return New(rdb, cfg)
}

// TestLifecycleOnRealRedis runs one session through every script — create,
// touch, rotate, revoke — and asserts the replies decode. The rotate leg is
// the sharp one: rotateScript writes deadline_ms back with Lua's tostring(),
// so the field survives only because Redis formats numbers with %.14g and a
// 13-digit millisecond deadline fits. Nothing in the code enforces that; this
// test is what would catch a formatting change, and gopher-lua would not.
func TestLifecycleOnRealRedis(t *testing.T) {
	_, rdb := testRedis(t)
	clk := newFakeClock()
	s := realStore(t, rdb, Config{Now: clk.Now, AbsoluteTTL: time.Hour})
	ctx := context.Background()

	tok, created := mustCreate(t, s, "acme", "alice")

	got, err := s.Validate(ctx, tok)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if got.ID != created.ID || got.UserID != "alice" || got.Realm != "acme" {
		t.Fatalf("session mismatch: got %+v, want %+v", got, created)
	}
	if !got.CreatedAt.Equal(created.CreatedAt) || !got.AbsDeadline.Equal(created.AbsDeadline) {
		t.Errorf("timestamps did not survive the round trip: got created=%v deadline=%v, want %v / %v",
			got.CreatedAt, got.AbsDeadline, created.CreatedAt, created.AbsDeadline)
	}

	clk.advance(5 * time.Minute)
	newTok, rotated, err := s.Rotate(ctx, tok, "198.51.100.9", "elevated/2.0")
	if err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	if !rotated.CreatedAt.Equal(created.CreatedAt) {
		t.Errorf("rotate lost CreatedAt: got %v, want %v", rotated.CreatedAt, created.CreatedAt)
	}
	if !rotated.AbsDeadline.Equal(created.AbsDeadline) {
		t.Errorf("rotate rewrote the absolute deadline: got %v, want %v", rotated.AbsDeadline, created.AbsDeadline)
	}
	if _, err := s.Validate(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Errorf("old token after rotate: got %v, want ErrNotFound", err)
	}
	// Re-read through Redis: the rotated record must still parse.
	if _, err := s.Validate(ctx, newTok); err != nil {
		t.Fatalf("rotated session did not survive a Redis round trip: %v", err)
	}
	// The index carries the original creation time, not the rotation time.
	sessions, err := s.List(ctx, "acme", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 || sessions[0].ID != rotated.ID {
		t.Fatalf("index after rotate: %+v", sessions)
	}

	if err := s.RevokeToken(ctx, newTok); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if _, err := s.Validate(ctx, newTok); !errors.Is(err, ErrNotFound) {
		t.Errorf("revoked token: got %v, want ErrNotFound", err)
	}
	if err := s.RevokeToken(ctx, newTok); err != nil {
		t.Errorf("revoke is not idempotent on real redis: %v", err)
	}
	if n, err := rdb.Exists(ctx, userKey("acme", "alice")).Result(); err != nil || n != 0 {
		t.Errorf("user index survived the last revoke: exists=%d err=%v", n, err)
	}
}

// TestRevokeUserOnRealRedis checks revokeUserScript's reply: it returns a Lua
// table of member strings, which go-redis must hand back as []any of strings
// for the broadcast loop to see anything at all. A reply that decodes to an
// empty list would silently skip every cache invalidation.
func TestRevokeUserOnRealRedis(t *testing.T) {
	_, rdb := testRedis(t)
	s := realStore(t, rdb, Config{Now: newFakeClock().Now})
	ctx := context.Background()

	toks := make([]string, 3)
	for i := range toks {
		toks[i], _ = mustCreate(t, s, "acme", "alice")
	}
	otherTok, _ := mustCreate(t, s, "acme", "bob")

	n, err := s.RevokeUser(ctx, "acme", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if n != len(toks) {
		t.Fatalf("RevokeUser reported %d sessions, want %d", n, len(toks))
	}
	for i, tok := range toks {
		if _, err := s.Validate(ctx, tok); !errors.Is(err, ErrNotFound) {
			t.Errorf("session %d after revoke-all: got %v, want ErrNotFound", i, err)
		}
	}
	if _, err := s.Validate(ctx, otherTok); err != nil {
		t.Errorf("bob's session was collateral damage: %v", err)
	}
}

// TestIdleTTLIsARealRedisTTL lets Redis expire the key on its own clock. The
// miniredis tests move time with FastForward, which proves the store's algebra
// but never that a PEXPIRE was issued with the value we think it was.
func TestIdleTTLIsARealRedisTTL(t *testing.T) {
	_, rdb := testRedis(t)
	s := realStore(t, rdb, Config{IdleTTL: time.Second})
	ctx := context.Background()

	tok, _ := mustCreate(t, s, "acme", "alice")
	time.Sleep(1500 * time.Millisecond)
	if _, err := s.Validate(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session outlived its idle TTL: got %v, want ErrNotFound", err)
	}
}

// TestTouchRenewsTheRealTTL reads PTTL straight from Redis: a touch must push
// the key's expiry back out to a full idle window.
func TestTouchRenewsTheRealTTL(t *testing.T) {
	_, rdb := testRedis(t)
	s := realStore(t, rdb, Config{IdleTTL: 10 * time.Second})
	ctx := context.Background()

	tok, sess := mustCreate(t, s, "acme", "alice")
	time.Sleep(1200 * time.Millisecond)

	before, err := rdb.PTTL(ctx, sessKey(sess.ID)).Result()
	if err != nil {
		t.Fatal(err)
	}
	if before > 9*time.Second {
		t.Fatalf("precondition: TTL %v has not decayed yet", before)
	}
	if _, err := s.Validate(ctx, tok); err != nil {
		t.Fatal(err)
	}
	after, err := rdb.PTTL(ctx, sessKey(sess.ID)).Result()
	if err != nil {
		t.Fatal(err)
	}
	if after <= before {
		t.Fatalf("touch did not renew the TTL: %v -> %v", before, after)
	}
}

// TestDeadlineRecheckOnRealRedis drives the branch a stale TTL would hide: the
// key is nowhere near expiry as far as Redis is concerned, but the caller's
// clock is past the absolute deadline. touchScript must refuse and delete it.
func TestDeadlineRecheckOnRealRedis(t *testing.T) {
	_, rdb := testRedis(t)
	clk := newFakeClock()
	// Real TTL of 10m; nothing expires during this test.
	s := realStore(t, rdb, Config{Now: clk.Now, IdleTTL: 10 * time.Minute, AbsoluteTTL: 10 * time.Minute})
	ctx := context.Background()

	tok, sess := mustCreate(t, s, "acme", "alice")
	clk.advance(11 * time.Minute) // the clock moves; the Redis TTL does not

	if n, err := rdb.Exists(ctx, sessKey(sess.ID)).Result(); err != nil || n != 1 {
		t.Fatalf("precondition: key should still be live in redis: exists=%d err=%v", n, err)
	}
	if _, err := s.Validate(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session past its deadline: got %v, want ErrNotFound", err)
	}
	if n, err := rdb.Exists(ctx, sessKey(sess.ID)).Result(); err != nil || n != 0 {
		t.Errorf("touch script left the expired session behind: exists=%d err=%v", n, err)
	}
}

// TestConcurrentCreateCapOnRealRedis is the miniredis cap race (see
// concurrency_test.go) re-run where EVAL atomicity is Redis's own, over a real
// connection pool. The Go-side regression is already caught for free there;
// this pins the remaining assumption, that a script Redis actually executes is
// one indivisible step.
func TestConcurrentCreateCapOnRealRedis(t *testing.T) {
	_, rdb := testRedis(t)
	const maxPerUser, callers = 5, 32
	s := realStore(t, rdb, Config{MaxPerUser: maxPerUser, Policy: Reject})
	ctx := context.Background()

	var wg sync.WaitGroup
	results := make([]error, callers)
	start := make(chan struct{})
	for i := range callers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, _, results[i] = s.Create(ctx, "acme", "alice", "127.0.0.1", "hammer")
		}(i)
	}
	close(start)
	wg.Wait()

	created := 0
	for i, err := range results {
		switch {
		case err == nil:
			created++
		case errors.Is(err, ErrSessionLimit):
		default:
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if created != maxPerUser {
		t.Errorf("%d concurrent creates succeeded, want exactly %d", created, maxPerUser)
	}
	sessions, err := s.List(ctx, "acme", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != maxPerUser {
		t.Errorf("%d live sessions, want %d", len(sessions), maxPerUser)
	}
}

// TestRevocationPropagatesOverRealPubSub replays the cross-node invalidation
// contract over Redis pub/sub rather than miniredis's in-process channels.
// CacheTTL is an hour, so only a delivered broadcast can explain node B
// dropping the session.
func TestRevocationPropagatesOverRealPubSub(t *testing.T) {
	url, rdbA := testRedis(t)
	rdbB := dial(t, url)
	cfg := Config{CacheTTL: time.Hour}
	nodeA := realStore(t, rdbA, cfg)
	nodeB := realStore(t, rdbB, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = nodeB.Run(ctx) }()
	waitSubscribedRedis(t, rdbA)

	tok, _ := mustCreate(t, nodeA, "acme", "alice")
	if _, err := nodeB.Validate(ctx, tok); err != nil {
		t.Fatalf("node B warm-up validate: %v", err)
	}
	if err := nodeA.RevokeToken(ctx, tok); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := nodeB.Validate(ctx, tok); errors.Is(err, ErrNotFound) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("revocation did not reach node B within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitSubscribedRedis blocks until Redis reports a subscriber on the
// revocation channel, so the test does not race the Subscribe handshake.
func waitSubscribedRedis(t *testing.T, rdb *redis.Client) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(2 * time.Second)
	for {
		counts, err := rdb.PubSubNumSub(ctx, revocationChannel).Result()
		if err != nil {
			t.Fatal(err)
		}
		if counts[revocationChannel] > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("node never subscribed to the revocation channel")
		}
		time.Sleep(2 * time.Millisecond)
	}
}
