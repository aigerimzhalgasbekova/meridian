// Package health implements a per-provider circuit breaker.
//
// bridge's availability is hostage to upstream identity providers it does not
// operate. When Microsoft has a bad day, the failure mode we refuse is the
// slow one: every /login/{provider} hanging for 10 seconds on a dead token
// endpoint, tying up connections and giving users a spinner instead of an
// answer. The breaker converts a misbehaving upstream into an immediate,
// explicit "this provider is down, here are alternatives" — failing fast is a
// feature, not a defeat.
//
// The state machine is the classic three-state breaker:
//
//	closed    normal operation; consecutive failures are counted
//	open      after Threshold consecutive failures; all calls rejected
//	          immediately until Cooldown has elapsed
//	half-open after Cooldown; exactly one probe call is admitted. Success
//	          closes the breaker, failure re-opens it for another Cooldown.
//
// Consecutive-failure counting (rather than a rate) is deliberate: bridge's
// upstream call volume is low and bursty (one discovery + one token exchange
// per login), so a rate window would be starved of samples. Five failures in
// a row from a single upstream is unambiguous.
package health

import (
	"errors"
	"sync"
	"time"
)

// State is a breaker state, exposed for /healthz/providers.
type State string

const (
	Closed   State = "closed"
	Open     State = "open"
	HalfOpen State = "half-open"
)

// ErrOpen is returned by Allow while the breaker is rejecting calls.
var ErrOpen = errors.New("health: circuit open, upstream provider marked unavailable")

// Breaker is a consecutive-failure circuit breaker. Safe for concurrent use.
type Breaker struct {
	threshold int
	cooldown  time.Duration
	now       func() time.Time

	mu       sync.Mutex
	failures int
	openedAt time.Time
	open     bool
	probing  bool // a half-open probe is in flight
}

// New builds a Breaker that opens after threshold consecutive failures and
// admits a probe after cooldown. now is injectable for tests (nil = time.Now).
func New(threshold int, cooldown time.Duration, now func() time.Time) *Breaker {
	if now == nil {
		now = time.Now
	}
	return &Breaker{threshold: threshold, cooldown: cooldown, now: now}
}

// Allow reports whether a call may proceed. In half-open state only one
// caller is admitted as the probe; concurrent callers get ErrOpen rather than
// stampeding a possibly-recovering upstream.
func (b *Breaker) Allow() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return nil
	}
	if b.now().Sub(b.openedAt) < b.cooldown {
		return ErrOpen
	}
	if b.probing {
		return ErrOpen
	}
	b.probing = true
	return nil
}

// Record reports the outcome of an admitted call.
func (b *Breaker) Record(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err == nil {
		b.open = false
		b.probing = false
		b.failures = 0
		return
	}
	b.probing = false
	b.failures++
	if b.open || b.failures >= b.threshold {
		b.open = true
		b.openedAt = b.now()
		b.failures = 0
	}
}

// errPanic is the outcome recorded for a guarded call that panicked.
var errPanic = errors.New("health: guarded call panicked")

// Do runs fn under the breaker: rejected immediately when open, outcome
// recorded otherwise.
//
// A panicking fn must still be recorded, and as a *failure*: Allow latches
// probing = true when it admits the half-open probe and only Record clears
// it, so an unrecorded panic wedges the breaker rejecting every caller
// forever — net/http recovers per connection, so nothing restarts the process
// to unwedge it. (Note the recover form is load-bearing: `defer b.Record(err)`
// on a named return would record err == nil during a panic and *close* the
// breaker, which is strictly worse.)
func (b *Breaker) Do(fn func() error) error {
	if err := b.Allow(); err != nil {
		return err
	}
	defer func() {
		if r := recover(); r != nil {
			b.Record(errPanic)
			panic(r)
		}
	}()
	err := fn()
	b.Record(err)
	return err
}

// State returns the current state for health reporting.
func (b *Breaker) State() State {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.open {
		return Closed
	}
	if b.now().Sub(b.openedAt) >= b.cooldown {
		return HalfOpen
	}
	return Open
}
