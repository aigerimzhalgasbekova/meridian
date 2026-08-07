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
	// Threshold is the number of consecutive failures that triggers an
	// account lockout (default 5). Consecutive, NOT per-window: the account
	// dimension exists to catch a distributed attacker guessing one victim's
	// password, and such an attacker only has to pace guesses under any
	// counting window to never trip it. The counter is cleared by Success
	// and by the entry going idle for FailWindow — both of which mean the
	// attack stopped — but never by the mere passage of time under load.
	Threshold int
	// IPThreshold is the number of failures per FailWindow from one IP that
	// triggers an IP lockout (default 10x Threshold). Deliberately higher than
	// Threshold: the IP counter aggregates failures across many accounts and
	// is NOT cleared by a success (see Success), so a shared egress — office
	// NAT, CGNAT, a mobile carrier — would self-lock at the per-account rate.
	IPThreshold int
	// BaseLock is the first lockout duration (default 1m). Each subsequent
	// lockout doubles it.
	BaseLock time.Duration
	// AccountCap bounds account-dimension lockout (default 15m). Low on
	// purpose: see the anti-DoS note in the package doc.
	AccountCap time.Duration
	// IPCap bounds IP-dimension lockout (default 24h). High on purpose:
	// escalation here only hurts the attacker's own address.
	IPCap time.Duration
	// FailWindow is the IP counting window — IPThreshold means "that many
	// failures per FailWindow", and IP escalation decays after a full quiet
	// window. It is also the idle expiry for BOTH dimensions: an entry
	// untouched for this long is forgotten entirely (default 1h).
	FailWindow time.Duration
	// MaxKeys bounds the tracked entries per dimension (default 100_000).
	// A credential-stuffing run walks a distinct username per attempt, and
	// nothing about a fresh entry is stale, so time-based expiry alone
	// cannot bound memory inside a single FailWindow. On overflow the
	// tracker reclaims stale entries, then unlocked ones; locked entries
	// are never evicted, because forgetting a lockout is what the attacker
	// is paying for. See the anti-DoS note in the package doc.
	MaxKeys int
}

func (p Policy) withDefaults() Policy {
	if p.Threshold <= 0 {
		p.Threshold = 5
	}
	if p.IPThreshold <= 0 {
		p.IPThreshold = 10 * p.Threshold
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
	if p.MaxKeys <= 0 {
		p.MaxKeys = 100_000
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
	fails       int       // failures since the last lock/success (per window on the IP dimension)
	lockLevel   int       // completed lockouts; drives exponential escalation
	lockedUntil time.Time // zero when not locked
	windowStart time.Time // start of the current FailWindow; IP dimension only
	touched     time.Time // last activity; drives expiry/GC only
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
	t.fail(t.accounts, account, Account, t.policy.Threshold, t.policy.AccountCap, now)
	t.fail(t.ips, ip, IP, t.policy.IPThreshold, t.policy.IPCap, now)
}

// sweepStale drops entries past FailWindow and no longer locked. Caller holds t.mu.
func (t *Tracker) sweepStale(m map[string]*state, now time.Time) {
	for k, s := range m {
		if now.Sub(s.touched) > t.policy.FailWindow && now.After(s.lockedUntil) {
			delete(m, k)
		}
	}
}

// reclaim makes room for a new key in m, returning false if the dimension is
// full of entries too valuable to drop.
//
// Triggering on size rather than on elapsed time is the whole point: a
// stuffing run walks a fresh username per attempt, so every entry is young and
// a time-based sweep reclaims nothing until the burst is long over. Stale
// entries go first; then unlocked ones, which are only failure counters below
// the threshold. A locked entry is never dropped — releasing a lockout early
// is precisely the outcome an attacker would be buying with the memory
// pressure. If everything is locked we stop tracking new keys in this
// dimension and lean on the other one (an attacker walking a million
// usernames still walks them from few IPs).
//
// Reclaiming down to a low-water mark rather than to exactly one free slot is
// load-bearing: freeing a single entry per insert would rescan the whole map
// on every subsequent failure, trading the memory DoS for a CPU one (measured
// at ~0.5ms per failed login at 50k keys). Batching amortizes the O(n) scan
// over the headroom it frees.
func (t *Tracker) reclaim(m map[string]*state, now time.Time) bool {
	if len(m) < t.policy.MaxKeys {
		return true
	}
	lowWater := t.policy.MaxKeys - t.policy.MaxKeys/10

	t.sweepStale(m, now)
	if len(m) <= lowWater {
		return true
	}
	for k, s := range m {
		if len(m) <= lowWater {
			break
		}
		if now.After(s.lockedUntil) {
			delete(m, k)
		}
	}
	return len(m) < t.policy.MaxKeys
}

// Success records a successful authentication. It resets failure state ONLY
// when neither dimension is locked: a success that lands while locked must
// not unlock — otherwise an attacker who finds the password mid-lockout
// converts the lockout into a free pass, and the lockout signal (which
// should page someone) is silently cleared.
//
// Only the ACCOUNT dimension is reset. The IP counter aggregates failures
// across many different accounts, so a success for one of them says nothing
// about the others — clearing it would let a sprayer wipe their own IP
// counter by logging into an account they control. The IP count is bounded
// instead by the FailWindow roll in fail(): IPThreshold means "that many
// failures per window", not "ever".
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
func (t *Tracker) fail(m map[string]*state, key string, dim Dimension, threshold int, cap time.Duration, now time.Time) {
	s, ok := m[key]
	if !ok || (now.Sub(s.touched) > t.policy.FailWindow && now.After(s.lockedUntil)) {
		if !ok && !t.reclaim(m, now) {
			return // dimension saturated; the other dimension still tracks this attempt
		}
		s = &state{windowStart: now}
		m[key] = s
	}
	s.touched = now
	if now.Before(s.lockedUntil) {
		// Failures during an active lock don't stack further locks; the
		// caller should have rejected before attempting auth at all.
		return
	}
	// Roll the counting window — IP dimension ONLY. The IP counter is never
	// cleared by a success (see Success), so without a roll a shared egress
	// (office NAT, CGNAT, a carrier) that fumbles a few passwords an hour
	// would accumulate forever, cross IPThreshold and lock every user behind
	// it, permanently, with no attacker present. It keys off windowStart, not
	// touched, because touched is refreshed by every failure.
	//
	// The account counter must NOT roll: a distributed attacker would just
	// pace guesses under the window (3/h at Threshold 5, FailWindow 1h = a
	// never-locking account) and that attacker is the entire reason the
	// account dimension exists. Nothing unbounded follows from a monotonic
	// account counter — Success clears the entry, and an idle FailWindow
	// sweeps it (sweepStale/lockLeft), so only an ongoing attack survives.
	if dim == IP && now.Sub(s.windowStart) > t.policy.FailWindow {
		s.fails = 0
		s.windowStart = now
		if now.Sub(s.lockedUntil) > t.policy.FailWindow {
			// A whole window passed with no lock in force: drop the
			// escalation too, or the next lock resumes at the old exponent
			// and yesterday's burst still costs 24h today.
			s.lockLevel = 0
		}
	}
	s.fails++
	if s.fails < threshold {
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
