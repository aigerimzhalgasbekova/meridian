package store

// Two Store instances sharing one miniredis simulate two sessiond nodes.
// These tests pin the distributed-invalidation contract: pub/sub makes
// revocation near-instant on listening nodes, and CacheTTL bounds staleness
// on nodes that missed the broadcast.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

func TestRevocationPropagatesAcrossNodes(t *testing.T) {
	mr := miniredis.RunT(t)
	clk := newFakeClock()
	// Cache TTL deliberately long: if node B drops the session quickly, it
	// was the pub/sub broadcast, not cache expiry.
	cfg := Config{CacheTTL: time.Hour}
	nodeA := testStore(t, mr, clk, cfg)
	nodeB := testStore(t, mr, clk, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = nodeB.Run(ctx) }()
	waitSubscribed(t, mr)

	tok, _ := mustCreate(t, nodeA, "acme", "alice")
	if _, err := nodeB.Validate(ctx, tok); err != nil {
		t.Fatalf("node B validate: %v", err)
	}

	if err := nodeA.RevokeToken(ctx, tok); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := nodeB.Validate(ctx, tok); errors.Is(err, ErrNotFound) {
			return // propagated
		}
		if time.Now().After(deadline) {
			t.Fatal("revocation did not propagate to node B within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRevokeUserPropagatesAcrossNodes(t *testing.T) {
	mr := miniredis.RunT(t)
	clk := newFakeClock()
	cfg := Config{CacheTTL: time.Hour}
	nodeA := testStore(t, mr, clk, cfg)
	nodeB := testStore(t, mr, clk, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = nodeB.Run(ctx) }()
	waitSubscribed(t, mr)

	tok1, _ := mustCreate(t, nodeA, "acme", "alice")
	tok2, _ := mustCreate(t, nodeA, "acme", "alice")
	for _, tok := range []string{tok1, tok2} {
		if _, err := nodeB.Validate(ctx, tok); err != nil {
			t.Fatalf("node B warm-up validate: %v", err)
		}
	}

	if _, err := nodeA.RevokeUser(ctx, "acme", "alice"); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for _, tok := range []string{tok1, tok2} {
		for {
			if _, err := nodeB.Validate(ctx, tok); errors.Is(err, ErrNotFound) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("global logout did not propagate to node B within 2s")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
}

func TestCacheStalenessBoundedWithoutPubSub(t *testing.T) {
	// Node B never runs the pub/sub loop — a worst-case node that misses
	// every broadcast. Its cache must still converge within CacheTTL.
	mr := miniredis.RunT(t)
	clk := newFakeClock()
	cacheTTL := 200 * time.Millisecond
	nodeA := testStore(t, mr, clk, Config{CacheTTL: cacheTTL})
	nodeB := testStore(t, mr, clk, Config{CacheTTL: cacheTTL})
	ctx := context.Background()

	tok, _ := mustCreate(t, nodeA, "acme", "alice")
	if _, err := nodeB.Validate(ctx, tok); err != nil {
		t.Fatal(err)
	}

	if err := nodeA.RevokeToken(ctx, tok); err != nil {
		t.Fatal(err)
	}

	// Within the window: node B may (and here does) serve the stale hit.
	// This is the documented bounded-staleness trade, not a bug.
	if _, err := nodeB.Validate(ctx, tok); err != nil {
		t.Fatalf("expected stale cache hit inside CacheTTL, got %v", err)
	}

	// Past the window the entry has expired and Redis is consulted.
	clk.advance(cacheTTL + time.Millisecond)
	if _, err := nodeB.Validate(ctx, tok); !errors.Is(err, ErrNotFound) {
		t.Fatalf("after CacheTTL: got %v, want ErrNotFound", err)
	}
}

func TestRotationInvalidatesOldIDAcrossNodes(t *testing.T) {
	mr := miniredis.RunT(t)
	clk := newFakeClock()
	cfg := Config{CacheTTL: time.Hour}
	nodeA := testStore(t, mr, clk, cfg)
	nodeB := testStore(t, mr, clk, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = nodeB.Run(ctx) }()
	waitSubscribed(t, mr)

	oldTok, _ := mustCreate(t, nodeA, "acme", "alice")
	if _, err := nodeB.Validate(ctx, oldTok); err != nil {
		t.Fatal(err)
	}

	newTok, _, err := nodeA.Rotate(ctx, oldTok, "", "")
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := nodeB.Validate(ctx, oldTok); errors.Is(err, ErrNotFound) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("rotated-out session still valid on node B after 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if _, err := nodeB.Validate(ctx, newTok); err != nil {
		t.Fatalf("rotated-in session on node B: %v", err)
	}
}

// waitSubscribed blocks until miniredis reports a subscriber on the
// revocation channel, so tests do not race the Subscribe handshake.
func waitSubscribed(t *testing.T, mr *miniredis.Miniredis) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if mr.PubSubNumSub(revocationChannel)[revocationChannel] > 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("node never subscribed to revocation channel")
		}
		time.Sleep(2 * time.Millisecond)
	}
}
