package ratelimit

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock {
	return &clock{t: time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)}
}
func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newLimiter(t *testing.T, p Policy, c *clock) *Limiter {
	t.Helper()
	l, err := New(NewMemStore(), map[string]Policy{"ip": p}, c.now)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func TestSustainedLimit(t *testing.T) {
	c := newClock()
	l := newLimiter(t, Policy{Limit: 5, Window: time.Minute}, c)

	for i := 0; i < 5; i++ {
		d, err := l.Allow("ip", "1.2.3.4")
		if err != nil {
			t.Fatal(err)
		}
		if !d.Allowed {
			t.Fatalf("request %d denied, want allowed", i+1)
		}
	}
	d, _ := l.Allow("ip", "1.2.3.4")
	if d.Allowed {
		t.Fatal("request 6 allowed, want denied")
	}
	// Denied hits count too, so the wait can exceed one window but never two.
	if d.RetryAfter <= 0 || d.RetryAfter > 2*time.Minute {
		t.Fatalf("RetryAfter = %v, want in (0, 2m]", d.RetryAfter)
	}
}

func TestKeysAreIndependent(t *testing.T) {
	c := newClock()
	l := newLimiter(t, Policy{Limit: 2, Window: time.Minute}, c)
	for i := 0; i < 3; i++ {
		l.Allow("ip", "attacker")
	}
	d, _ := l.Allow("ip", "innocent")
	if !d.Allowed {
		t.Fatal("unrelated key denied")
	}
}

func TestSlidingWindowSmoothsBoundary(t *testing.T) {
	// The fixed-window flaw: 5 requests at t=59s and 5 more at t=61s pass a
	// fixed 5/min window. The sliding window must deny the second burst.
	c := newClock()
	l := newLimiter(t, Policy{Limit: 5, Window: time.Minute}, c)

	c.advance(59 * time.Second)
	for i := 0; i < 5; i++ {
		if d, _ := l.Allow("ip", "k"); !d.Allowed {
			t.Fatalf("setup request %d denied", i+1)
		}
	}
	c.advance(2 * time.Second) // into the next fixed window
	denied := 0
	for i := 0; i < 5; i++ {
		if d, _ := l.Allow("ip", "k"); !d.Allowed {
			denied++
		}
	}
	if denied < 4 {
		t.Fatalf("only %d of 5 boundary-burst requests denied; fixed-window bypass", denied)
	}
}

func TestWindowDecayAllowsAgain(t *testing.T) {
	c := newClock()
	l := newLimiter(t, Policy{Limit: 5, Window: time.Minute}, c)
	for i := 0; i < 6; i++ {
		l.Allow("ip", "k")
	}
	d, _ := l.Allow("ip", "k")
	if d.Allowed {
		t.Fatal("still over limit, want denied")
	}
	c.advance(2 * time.Minute)
	d, _ = l.Allow("ip", "k")
	if !d.Allowed {
		t.Fatal("window fully expired, want allowed")
	}
}

func TestRetryAfterIsHonest(t *testing.T) {
	c := newClock()
	l := newLimiter(t, Policy{Limit: 5, Window: time.Minute}, c)
	for i := 0; i < 6; i++ {
		l.Allow("ip", "k")
	}
	d, _ := l.Allow("ip", "k")
	if d.Allowed {
		t.Fatal("want denied")
	}
	// Waiting the advertised time (plus the extra hit's decay) must succeed.
	c.advance(d.RetryAfter + time.Second)
	d2, _ := l.Allow("ip", "k")
	if !d2.Allowed {
		t.Fatalf("denied after waiting advertised RetryAfter=%v", d.RetryAfter)
	}
}

func TestBurstLimit(t *testing.T) {
	c := newClock()
	l := newLimiter(t, Policy{Limit: 100, Window: time.Minute, Burst: 3, BurstWindow: time.Second}, c)

	for i := 0; i < 3; i++ {
		if d, _ := l.Allow("ip", "k"); !d.Allowed {
			t.Fatalf("burst request %d denied", i+1)
		}
	}
	if d, _ := l.Allow("ip", "k"); d.Allowed {
		t.Fatal("4th request in 1s allowed despite Burst=3")
	}
	c.advance(3 * time.Second)
	if d, _ := l.Allow("ip", "k"); !d.Allowed {
		t.Fatal("burst window passed, sustained budget available, want allowed")
	}
}

func TestUnknownClassErrors(t *testing.T) {
	c := newClock()
	l := newLimiter(t, Policy{Limit: 5, Window: time.Minute}, c)
	if _, err := l.Allow("nope", "k"); err == nil {
		t.Fatal("unknown class must error, not silently allow")
	}
}

func TestPolicyValidation(t *testing.T) {
	for _, p := range []Policy{{}, {Limit: 5}, {Window: time.Minute}, {Limit: -1, Window: time.Minute}} {
		if _, err := New(NewMemStore(), map[string]Policy{"x": p}, nil); err == nil {
			t.Fatalf("policy %+v accepted, want error", p)
		}
	}
}

func TestConcurrentAllowCountsExactly(t *testing.T) {
	c := newClock()
	l := newLimiter(t, Policy{Limit: 100, Window: time.Minute}, c)

	var wg sync.WaitGroup
	allowed := make(chan bool, 200)
	for g := 0; g < 20; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 10; i++ {
				d, err := l.Allow("ip", "k")
				if err != nil {
					t.Error(err)
					return
				}
				allowed <- d.Allowed
			}
		}()
	}
	wg.Wait()
	close(allowed)
	n := 0
	for a := range allowed {
		if a {
			n++
		}
	}
	if n != 100 {
		t.Fatalf("allowed %d of 200 concurrent requests, want exactly 100", n)
	}
}

func BenchmarkAllow(b *testing.B) {
	l, err := New(NewMemStore(), map[string]Policy{
		"ip": {Limit: 1000000, Window: time.Minute, Burst: 100000, BurstWindow: time.Second},
	}, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			if _, err := l.Allow("ip", fmt.Sprintf("10.0.0.%d", i%256)); err != nil {
				b.Fatal(err)
			}
		}
	})
}
