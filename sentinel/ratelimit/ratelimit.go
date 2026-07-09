// Package ratelimit implements a sliding-window-counter rate limiter.
//
// Algorithm (ADR 0001): two fixed-window counters per key (current +
// previous window); the effective count is cur + prev weighted by how much
// of the previous window still overlaps the sliding window. This gives
// near-sliding-log accuracy at O(1) memory per key, and — unlike a token
// bucket — the state is two integers that map directly onto atomic Redis
// INCR/EXPIRE, which is what "distributed" requires.
//
// Denied requests still count: a client hammering past its limit keeps
// itself limited, which is the desired posture against abuse (Retry-After
// tells well-behaved clients when to come back).
//
// Policies pair a sustained rate (Limit per Window) with a burst rate
// (Burst per BurstWindow): sustained caps the average, burst caps spikes.
// Key classes ("ip", "user", "client") each carry their own policy; callers
// choose the class and the key.
package ratelimit

import (
	"fmt"
	"sync"
	"time"
)

// Store holds window counters. Implementations must make Hit atomic per key.
//
// This is the Redis seam: a Redis store implements Hit as a small Lua script
// (INCR current-window key, GET previous-window key, EXPIRE both to 2×window)
// so multiple sentinel instances share limits. The in-memory store below is
// the single-instance / test implementation.
type Store interface {
	// Hit records one request against key's window starting at start and
	// returns the current-window count (including this hit) and the count
	// of the immediately preceding window.
	Hit(key string, start time.Time, window time.Duration) (cur, prev int64, err error)
}

// Policy is a burst + sustained rate for one key class.
type Policy struct {
	Limit  int           // max requests per Window (sliding)
	Window time.Duration // sustained window, e.g. 1m
	Burst  int           // max requests per BurstWindow; 0 disables burst check
	// BurstWindow defaults to Window/10 when Burst > 0.
	BurstWindow time.Duration
}

func (p Policy) validate(class string) error {
	if p.Limit <= 0 || p.Window <= 0 {
		return fmt.Errorf("ratelimit: class %q: Limit and Window must be positive", class)
	}
	if p.Burst < 0 || (p.Burst > 0 && p.BurstWindow < 0) {
		return fmt.Errorf("ratelimit: class %q: negative burst configuration", class)
	}
	return nil
}

// Decision is the outcome of one Allow call.
type Decision struct {
	Allowed bool
	// Remaining is a conservative estimate of requests left in the
	// sustained window.
	Remaining int
	// RetryAfter is how long until a request could next succeed; zero when
	// allowed. Suitable for a Retry-After header (round up to seconds).
	RetryAfter time.Duration
}

// Limiter applies per-class policies over a Store. Safe for concurrent use.
type Limiter struct {
	store    Store
	policies map[string]Policy
	now      func() time.Time
}

// New builds a limiter. policies maps key class → policy.
func New(store Store, policies map[string]Policy, now func() time.Time) (*Limiter, error) {
	if now == nil {
		now = time.Now
	}
	ps := make(map[string]Policy, len(policies))
	for class, p := range policies {
		if err := p.validate(class); err != nil {
			return nil, err
		}
		if p.Burst > 0 && p.BurstWindow == 0 {
			p.BurstWindow = p.Window / 10
			if p.BurstWindow <= 0 {
				p.BurstWindow = time.Second
			}
		}
		ps[class] = p
	}
	return &Limiter{store: store, policies: ps, now: now}, nil
}

// Allow records a request for key under class's policy and decides it.
// Unknown classes are rejected loudly — a typo must not mean "unlimited".
func (l *Limiter) Allow(class, key string) (Decision, error) {
	p, ok := l.policies[class]
	if !ok {
		return Decision{}, fmt.Errorf("ratelimit: unknown key class %q", class)
	}
	now := l.now()

	d, err := l.check(class+":"+key+":s", p.Limit, p.Window, now)
	if err != nil {
		return Decision{}, err
	}
	if p.Burst > 0 {
		bd, err := l.check(class+":"+key+":b", p.Burst, p.BurstWindow, now)
		if err != nil {
			return Decision{}, err
		}
		// The stricter verdict wins; report the shorter useful wait.
		if !bd.Allowed && (d.Allowed || bd.RetryAfter > d.RetryAfter) {
			bd.Remaining = min(bd.Remaining, d.Remaining)
			d = bd
		}
		if d.Allowed {
			d.Remaining = min(d.Remaining, bd.Remaining)
		}
	}
	return d, nil
}

func (l *Limiter) check(storeKey string, limit int, window time.Duration, now time.Time) (Decision, error) {
	start := now.Truncate(window)
	cur, prev, err := l.store.Hit(storeKey, start, window)
	if err != nil {
		return Decision{}, err
	}
	elapsed := now.Sub(start)
	// Fraction of the previous window still inside the sliding window.
	frac := 1 - float64(elapsed)/float64(window)
	weighted := float64(cur) + float64(prev)*frac
	if weighted <= float64(limit) {
		return Decision{Allowed: true, Remaining: int(float64(limit) - weighted)}, nil
	}
	return Decision{RetryAfter: retryAfter(cur, prev, limit, window, elapsed)}, nil
}

// retryAfter estimates when the weighted count decays enough that one more
// request fits.
func retryAfter(cur, prev int64, limit int, window time.Duration, elapsed time.Duration) time.Duration {
	if cur >= int64(limit) {
		// The current window alone is full: nothing succeeds until it
		// rolls over AND, as the new previous window, decays enough that
		// cur*frac + 1 <= limit.
		frac := float64(limit-1) / float64(cur)
		return (window - elapsed) + time.Duration((1-frac)*float64(window))
	}
	// Need prev*frac + cur + 1 <= limit  ⇒  frac <= (limit-cur-1)/prev.
	frac := float64(int64(limit)-cur-1) / float64(prev)
	wait := time.Duration((1-frac)*float64(window)) - elapsed
	if wait < 0 {
		wait = 0
	}
	return wait
}

// MemStore is the in-memory Store. Two counters per key; stale entries are
// swept lazily.
type MemStore struct {
	mu   sync.Mutex
	m    map[string]*windows
	hits int
}

type windows struct {
	start time.Time
	dur   time.Duration
	cur   int64
	prev  int64
}

func NewMemStore() *MemStore { return &MemStore{m: make(map[string]*windows)} }

func (s *MemStore) Hit(key string, start time.Time, window time.Duration) (int64, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	w, ok := s.m[key]
	if !ok {
		w = &windows{start: start, dur: window}
		s.m[key] = w
	}
	switch {
	case start.Equal(w.start):
		// same window
	case start.Equal(w.start.Add(window)):
		w.prev, w.cur = w.cur, 0
		w.start = start
	default:
		// Jumped more than one window: history no longer overlaps.
		w.prev, w.cur = 0, 0
		w.start = start
	}
	w.cur++

	// ponytail: amortized sweep every 4096 hits bounds map growth; a Redis
	// store gets this for free via EXPIRE.
	s.hits++
	if s.hits%4096 == 0 {
		for k, w := range s.m {
			if start.Sub(w.start) > 2*w.dur {
				delete(s.m, k)
			}
		}
	}
	return w.cur, w.prev, nil
}
