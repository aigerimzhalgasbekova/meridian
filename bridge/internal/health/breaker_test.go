package health

import (
	"errors"
	"testing"
	"time"
)

func TestBreaker(t *testing.T) {
	fail := errors.New("boom")
	clock := time.Unix(1_700_000_000, 0)
	now := func() time.Time { return clock }
	b := New(3, time.Minute, func() time.Time { return now() })

	t.Run("opens after threshold consecutive failures", func(t *testing.T) {
		for i := 0; i < 2; i++ {
			if err := b.Do(func() error { return fail }); !errors.Is(err, fail) {
				t.Fatalf("call %d: got %v", i, err)
			}
			if got := b.State(); got != Closed {
				t.Fatalf("after %d failures state = %s, want closed", i+1, got)
			}
		}
		if err := b.Do(func() error { return fail }); !errors.Is(err, fail) {
			t.Fatalf("third failure: %v", err)
		}
		if got := b.State(); got != Open {
			t.Fatalf("state = %s, want open", got)
		}
		if err := b.Do(func() error { t.Fatal("must not run"); return nil }); !errors.Is(err, ErrOpen) {
			t.Fatalf("open breaker admitted a call: %v", err)
		}
	})

	t.Run("half-opens after cooldown, failure re-opens", func(t *testing.T) {
		clock = clock.Add(time.Minute)
		if got := b.State(); got != HalfOpen {
			t.Fatalf("state = %s, want half-open", got)
		}
		if err := b.Do(func() error { return fail }); !errors.Is(err, fail) {
			t.Fatalf("probe: %v", err)
		}
		if got := b.State(); got != Open {
			t.Fatalf("state after failed probe = %s, want open", got)
		}
	})

	t.Run("successful probe closes", func(t *testing.T) {
		clock = clock.Add(time.Minute)
		if err := b.Do(func() error { return nil }); err != nil {
			t.Fatalf("probe: %v", err)
		}
		if got := b.State(); got != Closed {
			t.Fatalf("state = %s, want closed", got)
		}
	})

	t.Run("success resets consecutive counter", func(t *testing.T) {
		b := New(3, time.Minute, now)
		b.Do(func() error { return fail })
		b.Do(func() error { return fail })
		b.Do(func() error { return nil })
		b.Do(func() error { return fail })
		b.Do(func() error { return fail })
		if got := b.State(); got != Closed {
			t.Fatalf("state = %s, want closed (counter should reset on success)", got)
		}
	})

	// Allow latches probing = true and only Record clears it, so a panicking
	// guarded call that never reaches Record wedges the breaker rejecting
	// every caller forever — net/http recovers per connection, so nothing
	// restarts the process to unwedge it.
	t.Run("panicking probe does not wedge the breaker", func(t *testing.T) {
		b := New(1, time.Minute, now)
		b.Do(func() error { return fail })
		clock = clock.Add(time.Minute)
		func() {
			defer func() { recover() }()
			b.Do(func() error { panic("upstream parser blew up") })
		}()
		// The panic counts as a failure, so the breaker re-opened: after
		// another cooldown it must admit a probe again.
		clock = clock.Add(time.Minute)
		if err := b.Allow(); err != nil {
			t.Fatalf("breaker wedged after a panicking probe: %v", err)
		}
		b.Record(nil)
		if got := b.State(); got != Closed {
			t.Fatalf("state = %s, want closed", got)
		}
	})

	t.Run("half-open admits only one probe", func(t *testing.T) {
		b := New(1, time.Minute, now)
		b.Do(func() error { return fail })
		clock = clock.Add(time.Minute)
		if err := b.Allow(); err != nil {
			t.Fatalf("first probe rejected: %v", err)
		}
		if err := b.Allow(); !errors.Is(err, ErrOpen) {
			t.Fatalf("second concurrent probe admitted: %v", err)
		}
		b.Record(nil)
		if got := b.State(); got != Closed {
			t.Fatalf("state = %s, want closed", got)
		}
	})
}
