// Package lockout implements escalating brute-force lockout on failed
// authentication.
//
// Two dimensions are tracked SEPARATELY, and both must be checked:
//
//   - Per-account: catches a distributed attacker (botnet, many IPs) trying
//     one victim's password. IP-only tracking is blind to this.
//   - Per-IP: catches one host spraying many accounts (password spraying at
//     a few attempts per account, staying under every account threshold).
//     Account-only tracking is blind to this.
//
// Anti-DoS design (ADR 0002): account lockout is attacker-controlled — an
// attacker who knows a victim's username can fail logins on purpose and lock
// the victim out forever. So the account dimension escalates but is CAPPED
// (default 15m): the victim is inconvenienced, never bricked. The IP
// dimension is where unbounded escalation is safe (the attacker only locks
// out their own address) and gets a much higher cap. The residual gap — a
// distributed attacker repeatedly re-locking one account at the cap — is
// handled by the ChallengeHook seam: after repeated account lockouts,
// require CAPTCHA / step-up instead of longer lockout.
//
// Timing safety: Check performs identical work on the locked and unlocked
// paths (no early return before both dimensions are read). Callers must
// return the same uniform "invalid credentials" response — with the same
// response time — whether the account is locked, nonexistent, or the
// password is merely wrong; anything else is a lockout-state oracle that
// confirms valid usernames.
package lockout

import (
	"sync"
	"time"
)

// Dimension names which tracking dimension triggered.
type Dimension string

const (
	Account Dimension = "account"
	IP      Dimension = "ip"
)

// Policy configures escalation.
type Policy struct {
	// Threshold is the number of consecutive failures that triggers a
	// lockout (default 5).
	Threshold int
	// BaseLock is the first lockout duration (default 1m). Each subsequent
	// lockout doubles it.
	BaseLock time.Duration
	// AccountCap bounds account-dimension lockout (default 15m). Low on
	// purpose: see the anti-DoS note in the package doc.
	AccountCap time.Duration
	// IPCap bounds IP-dimension lockout (default 24h). High on purpose:
	// escalation here only hurts the attacker's own address.
	IPCap time.Duration
	// FailWindow expires stale failure counts and escalation state; an
	// entry untouched for this long is forgotten (default 1h).
	FailWindow time.Duration
}

func (p Policy) withDefaults() Policy {
	if p.Threshold <= 0 {
		p.Threshold = 5
	}
	if p.BaseLock <= 0 {
		p.BaseLock = time.Minute
	}
	if p.AccountCap <= 0 {
		p.AccountCap = 15 * time.Minute
	}
	if p.IPCap <= 0 {
		p.IPCap = 24 * time.Hour
	}
	if p.FailWindow <= 0 {
		p.FailWindow = time.Hour
	}
	return p
}

// Decision reports lockout state for one (account, IP) pair.
type Decision struct {
	Locked     bool
	Dimension  Dimension     // which dimension is locked (account wins ties)
	RetryAfter time.Duration // time until the lock expires
}

type state struct {
	fails       int       // consecutive failures since last lock/success
	lockLevel   int       // completed lockouts; drives exponential escalation
	lockedUntil time.Time // zero when not locked
	touched     time.Time // for FailWindow expiry
}

// Tracker tracks failures and lockouts in memory. Safe for concurrent use.
//
// Storage seam: state is two small maps keyed by string; a Redis
// implementation is a hash per key with EXPIRE = FailWindow, letting
// multiple sentinel instances share lockout state.
type Tracker struct {
	mu       sync.Mutex
	policy   Policy
	now      func() time.Time
	accounts map[string]*state
	ips      map[string]*state

	// ChallengeHook, when set, is called each time a dimension locks —
	// the seam for CAPTCHA / step-up flows and lockout alerting. Called
	// synchronously with the tracker lock held; keep it cheap (enqueue).
	ChallengeHook func(dim Dimension, key string, lockLevel int)
}

// New builds a tracker; zero-valued policy fields get defaults.
func New(policy Policy, now func() time.Time) *Tracker {
	if now == nil {
		now = time.Now
	}
	return &Tracker{
		policy:   policy.withDefaults(),
		now:      now,
		accounts: make(map[string]*state),
		ips:      make(map[string]*state),
	}
}

// Check reports whether account or ip is currently locked. It never mutates
// failure counts. Both dimensions are always evaluated (uniform work).
func (t *Tracker) Check(account, ip string) Decision {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	accLeft := t.lockLeft(t.accounts, account, now)
	ipLeft := t.lockLeft(t.ips, ip, now)
	switch {
	case accLeft > 0:
		return Decision{Locked: true, Dimension: Account, RetryAfter: accLeft}
	case ipLeft > 0:
		return Decision{Locked: true, Dimension: IP, RetryAfter: ipLeft}
	default:
		return Decision{}
	}
}

// Fail records a failed authentication attempt for both dimensions.
func (t *Tracker) Fail(account, ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	t.fail(t.accounts, account, Account, t.policy.AccountCap, now)
	t.fail(t.ips, ip, IP, t.policy.IPCap, now)
}

// Success records a successful authentication. It resets failure state ONLY
// when neither dimension is locked: a success that lands while locked must
// not unlock — otherwise an attacker who finds the password mid-lockout
// converts the lockout into a free pass, and the lockout signal (which
// should page someone) is silently cleared.
func (t *Tracker) Success(account, ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	accLocked := t.lockLeft(t.accounts, account, now) > 0
	ipLocked := t.lockLeft(t.ips, ip, now) > 0
	if accLocked || ipLocked {
		return
	}
	delete(t.accounts, account)
	delete(t.ips, ip)
}

// lockLeft returns remaining lock time for key, expiring stale entries.
// Caller holds t.mu.
func (t *Tracker) lockLeft(m map[string]*state, key string, now time.Time) time.Duration {
	s, ok := m[key]
	if !ok {
		return 0
	}
	if now.Sub(s.touched) > t.policy.FailWindow && now.After(s.lockedUntil) {
		delete(m, key)
		return 0
	}
	if left := s.lockedUntil.Sub(now); left > 0 {
		return left
	}
	return 0
}

// fail increments key's failure count and locks on threshold. Caller holds t.mu.
func (t *Tracker) fail(m map[string]*state, key string, dim Dimension, cap time.Duration, now time.Time) {
	s, ok := m[key]
	if !ok || (now.Sub(s.touched) > t.policy.FailWindow && now.After(s.lockedUntil)) {
		s = &state{}
		m[key] = s
	}
	s.touched = now
	if now.Before(s.lockedUntil) {
		// Failures during an active lock don't stack further locks; the
		// caller should have rejected before attempting auth at all.
		return
	}
	s.fails++
	if s.fails < t.policy.Threshold {
		return
	}
	// Escalate: BaseLock * 2^lockLevel, capped per dimension.
	d := t.policy.BaseLock << s.lockLevel
	if d > cap || d <= 0 { // <=0 guards shift overflow
		d = cap
	}
	s.lockedUntil = now.Add(d)
	s.lockLevel++
	s.fails = 0
	if t.ChallengeHook != nil {
		t.ChallengeHook(dim, key, s.lockLevel)
	}
}
