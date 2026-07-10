package store

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
)

// concurrentCreates fires n Create calls for one user from a standing start
// and returns their errors in call order.
func concurrentCreates(t *testing.T, s *Store, n int) []error {
	t.Helper()
	ctx := context.Background()
	errs := make([]error, n)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, _, errs[i] = s.Create(ctx, "acme", "alice", "127.0.0.1", "hammer")
		}(i)
	}
	close(start)
	wg.Wait()
	return errs
}

// TestConcurrentCreateRejectsPastCap and its evict-oldest twin are the tests
// that hold createScript to being *one* script. The suite's other cap tests
// call Create sequentially, so a cap enforced by a prune/count/write sequence
// of separate round trips passes them all: each caller reads a count that a
// racing caller is about to invalidate. Firing the creates in parallel is what
// exposes it — replacing the script with client-side round trips lets 16-29 of
// 32 callers through here.
func TestConcurrentCreateRejectsPastCap(t *testing.T) {
	mr := miniredis.RunT(t)
	const maxPerUser, callers = 5, 32
	s := testStore(t, mr, newFakeClock(), Config{
		MaxPerUser: maxPerUser, Policy: Reject, CacheTTL: time.Millisecond,
	})

	created := 0
	for i, err := range concurrentCreates(t, s, callers) {
		switch {
		case err == nil:
			created++
		case errors.Is(err, ErrSessionLimit):
		default:
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	if created != maxPerUser {
		t.Errorf("%d of %d concurrent creates succeeded, want exactly %d", created, callers, maxPerUser)
	}
	sessions, err := s.List(context.Background(), "acme", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != maxPerUser {
		t.Errorf("%d live sessions, want %d", len(sessions), maxPerUser)
	}
}

func TestConcurrentCreateEvictOldestHoldsCap(t *testing.T) {
	mr := miniredis.RunT(t)
	const maxPerUser, callers = 5, 32
	s := testStore(t, mr, newFakeClock(), Config{MaxPerUser: maxPerUser, CacheTTL: time.Millisecond})

	// Under evict-oldest every caller succeeds; the cap holds by eviction.
	for i, err := range concurrentCreates(t, s, callers) {
		if err != nil {
			t.Fatalf("caller %d: %v", i, err)
		}
	}
	sessions, err := s.List(context.Background(), "acme", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != maxPerUser {
		t.Errorf("%d live sessions after %d concurrent creates, cap is %d", len(sessions), callers, maxPerUser)
	}
}

// TestConcurrentHammer runs create/validate/rotate/revoke in parallel from
// two nodes against one Redis and checks the invariants that must survive any
// interleaving: no error other than the sentinel ones, and the per-user cap
// never exceeded. Run with -race.
func TestConcurrentHammer(t *testing.T) {
	mr := miniredis.RunT(t)
	clk := newFakeClock()
	const maxPerUser = 5
	cfg := Config{MaxPerUser: maxPerUser, CacheTTL: 50 * time.Millisecond}
	nodes := []*Store{
		testStore(t, mr, clk, cfg),
		testStore(t, mr, clk, cfg),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for _, n := range nodes {
		n := n
		go func() { _ = n.Run(ctx) }()
	}

	users := []string{"alice", "bob", "carol"}
	const workers = 12
	const iters = 40

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			node := nodes[w%len(nodes)]
			user := users[w%len(users)]
			for i := 0; i < iters; i++ {
				tok, _, err := node.Create(ctx, "acme", user, "127.0.0.1", "hammer")
				if err != nil {
					t.Errorf("create: %v", err)
					return
				}
				switch i % 4 {
				case 0:
					if _, err := node.Validate(ctx, tok); err != nil && !errors.Is(err, ErrNotFound) {
						// ErrNotFound is legal: another worker's create may
						// have evicted this session already.
						t.Errorf("validate: %v", err)
						return
					}
				case 1:
					if _, _, err := node.Rotate(ctx, tok, "", ""); err != nil && !errors.Is(err, ErrNotFound) {
						t.Errorf("rotate: %v", err)
						return
					}
				case 2:
					if err := node.RevokeToken(ctx, tok); err != nil {
						t.Errorf("revoke: %v", err)
						return
					}
				case 3:
					// Occasionally nuke the whole user from the other node.
					other := nodes[(w+1)%len(nodes)]
					if _, err := other.RevokeUser(ctx, "acme", user); err != nil {
						t.Errorf("revoke user: %v", err)
						return
					}
				}
			}
		}(w)
	}
	wg.Wait()

	// Invariant: the cap held for every user, on every node's view.
	for _, user := range users {
		for i, n := range nodes {
			sessions, err := n.List(ctx, "acme", user)
			if err != nil {
				t.Fatalf("list %s on node %d: %v", user, i, err)
			}
			if len(sessions) > maxPerUser {
				t.Errorf("user %s has %d live sessions on node %d, cap is %d",
					user, len(sessions), i, maxPerUser)
			}
		}
	}
}
