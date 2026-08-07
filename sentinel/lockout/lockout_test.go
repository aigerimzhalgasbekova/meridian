package lockout

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

var testPolicy = Policy{
	Threshold: 3,
	// Same as Threshold so the two-dimension tests below stay readable; the
	// production default is 10x Threshold (see Policy.IPThreshold).
	IPThreshold: 3,
	BaseLock:    time.Minute,
	AccountCap:  4 * time.Minute,
	IPCap:       time.Hour,
	FailWindow:  time.Hour,
}

func failN(t *Tracker, account, ip string, n int) {
	for i := 0; i < n; i++ {
		t.Fail(account, ip)
	}
}

func TestLockAfterThreshold(t *testing.T) {
	c := newClock()
	tr := New(testPolicy, c.now)

	failN(tr, "alice", "1.1.1.1", 2)
	if d := tr.Check("alice", "1.1.1.1"); d.Locked {
		t.Fatal("locked below threshold")
	}
	tr.Fail("alice", "1.1.1.1")
	d := tr.Check("alice", "1.1.1.1")
	if !d.Locked || d.Dimension != Account {
		t.Fatalf("want account lock, got %+v", d)
	}
	if d.RetryAfter != time.Minute {
		t.Fatalf("first lock = %v, want 1m", d.RetryAfter)
	}
}

func TestEscalationDoublesAndCaps(t *testing.T) {
	c := newClock()
	tr := New(testPolicy, c.now)

	wants := []time.Duration{
		time.Minute,     // lock 1
		2 * time.Minute, // lock 2
		4 * time.Minute, // lock 3 = account cap
		4 * time.Minute, // lock 4: capped, not 8m
	}
	for i, want := range wants {
		failN(tr, "alice", "1.1.1.1", testPolicy.Threshold)
		d := tr.Check("alice", "1.1.1.1")
		if !d.Locked || d.RetryAfter != want {
			t.Fatalf("lock %d: got %+v, want RetryAfter %v", i+1, d, want)
		}
		c.advance(d.RetryAfter + time.Second)
	}
}

func TestDimensionsIndependent(t *testing.T) {
	c := newClock()
	tr := New(testPolicy, c.now)

	// Password spraying: one IP, many accounts, sub-threshold per account.
	for _, acct := range []string{"a", "b", "c"} {
		tr.Fail(acct, "6.6.6.6")
	}
	if d := tr.Check("a", "6.6.6.6"); !d.Locked || d.Dimension != IP {
		t.Fatalf("spraying IP not locked: %+v", d)
	}
	// Fresh account from the sprayed IP is blocked; same account from a
	// clean IP is not.
	if d := tr.Check("zoe", "6.6.6.6"); !d.Locked {
		t.Fatal("sprayed IP allowed via new account")
	}
	if d := tr.Check("a", "9.9.9.9"); d.Locked {
		t.Fatal("account locked by IP-dimension failures alone")
	}

	// Distributed attack: one account, many IPs.
	tr2 := New(testPolicy, c.now)
	tr2.Fail("victim", "1.0.0.1")
	tr2.Fail("victim", "1.0.0.2")
	tr2.Fail("victim", "1.0.0.3")
	if d := tr2.Check("victim", "1.0.0.99"); !d.Locked || d.Dimension != Account {
		t.Fatalf("distributed attack on one account not locked: %+v", d)
	}
}

func TestAccountLockoutIsCappedAgainstDoS(t *testing.T) {
	c := newClock()
	tr := New(testPolicy, c.now)

	// Attacker fails logins against the victim for hours.
	for i := 0; i < 50; i++ {
		failN(tr, "victim", "6.6.6.6", testPolicy.Threshold)
		c.advance(testPolicy.AccountCap + time.Second)
	}
	failN(tr, "victim", "6.6.6.6", testPolicy.Threshold)
	d := tr.Check("victim", "6.6.6.6")
	if !d.Locked {
		t.Fatal("want locked")
	}
	if d.RetryAfter > testPolicy.AccountCap {
		t.Fatalf("account lock %v exceeds cap %v: attacker-controlled DoS", d.RetryAfter, testPolicy.AccountCap)
	}
}

func TestSuccessResetsOnlyWhenUnlocked(t *testing.T) {
	c := newClock()
	tr := New(testPolicy, c.now)

	// Success while locked must NOT unlock.
	failN(tr, "alice", "1.1.1.1", testPolicy.Threshold)
	tr.Success("alice", "1.1.1.1")
	if d := tr.Check("alice", "1.1.1.1"); !d.Locked {
		t.Fatal("success during lockout cleared the lock")
	}

	// After the lock expires, success clears failure and escalation state.
	c.advance(2 * time.Minute)
	tr.Success("alice", "1.1.1.1")
	failN(tr, "alice", "1.1.1.1", testPolicy.Threshold)
	d := tr.Check("alice", "1.1.1.1")
	if !d.Locked || d.RetryAfter != time.Minute {
		t.Fatalf("escalation not reset by success: %+v", d)
	}
}

// A sprayer used to reset their own IP counter by logging into an account
// they control: Success deleted the whole IP entry, so the IP dimension —
// the one ADR 0002 added to catch "one host, many accounts" — never reached
// its threshold no matter how many victims were walked.
func TestIPDimensionSurvivesInterleavedSuccess(t *testing.T) {
	c := newClock()
	tr := New(testPolicy, c.now)

	for i := 0; i < 10; i++ {
		tr.Fail(fmt.Sprintf("victim-%d", i), "10.0.0.1")
		tr.Success("attacker-own-account", "10.0.0.1")
	}
	if d := tr.Check("someone-else", "10.0.0.1"); !d.Locked || d.Dimension != IP {
		t.Fatalf("sprayed IP not locked after interleaved successes: %+v", d)
	}
}

// The flip side: an office NAT where real users occasionally fumble a
// password must not lock its whole egress. The IP threshold is 10x the
// account one for exactly this reason.
func TestSharedEgressDoesNotSelfLock(t *testing.T) {
	c := newClock()
	policy := Policy{Threshold: 5} // IPThreshold defaults to 50
	tr := New(policy, c.now)

	// 40 users, one fumbled password each, each followed by a success.
	for i := 0; i < 40; i++ {
		acct := fmt.Sprintf("employee-%d", i)
		tr.Fail(acct, "198.51.100.7")
		tr.Success(acct, "198.51.100.7")
	}
	if d := tr.Check("employee-41", "198.51.100.7"); d.Locked {
		t.Fatalf("shared egress locked itself out on normal traffic: %+v", d)
	}
}

// The IP counter is never cleared by a success, so it stays bounded only if
// the counting window actually rolls. Keying the reset off `touched` — which
// every failure refreshes — makes it monotonic instead: an office NAT that
// fumbles 40 passwords an hour crosses IPThreshold (50) partway through the
// second hour and, since lockLevel never decays either, escalates to a 24h
// lock and stays there. Sustained sub-threshold traffic must never lock.
func TestSharedEgressSurvivesSustainedTraffic(t *testing.T) {
	c := newClock()
	tr := New(Policy{Threshold: 5}, c.now) // IPThreshold 50, FailWindow 1h
	const perHour = 40                     // below IPThreshold, sustained forever

	for hour := 0; hour < 72; hour++ {
		for i := 0; i < perHour; i++ {
			acct := fmt.Sprintf("employee-%d", i)
			tr.Fail(acct, "198.51.100.7")
			tr.Success(acct, "198.51.100.7")
			c.advance(time.Hour / perHour)
			if d := tr.Check("employee-0", "198.51.100.7"); d.Locked {
				t.Fatalf("shared egress locked itself out at hour %d: %+v", hour, d)
			}
		}
	}

	// Escalation decays with the window too: a key that keeps seeing traffic
	// (so it is never swept as stale) but goes a full window without locking
	// starts over at BaseLock, instead of resuming yesterday's exponent.
	c2 := newClock()
	tr2 := New(testPolicy, c2.now) // Threshold 3, BaseLock 1m, FailWindow 1h
	failN(tr2, "alice", "1.1.1.1", testPolicy.Threshold)
	if d := tr2.Check("alice", "1.1.1.1"); d.RetryAfter != time.Minute {
		t.Fatalf("first lock = %v, want 1m", d.RetryAfter)
	}
	for i := 0; i < 4; i++ { // 2h of one failure per 30m: sub-threshold, never stale
		c2.advance(30 * time.Minute)
		tr2.Fail("alice", "1.1.1.1")
		if d := tr2.Check("alice", "1.1.1.1"); d.Locked {
			t.Fatalf("sub-threshold trickle locked the account: %+v", d)
		}
	}
	failN(tr2, "alice", "1.1.1.1", testPolicy.Threshold)
	if d := tr2.Check("alice", "1.1.1.1"); !d.Locked || d.RetryAfter != testPolicy.BaseLock {
		t.Fatalf("escalation did not decay after a quiet window: %+v", d)
	}
}

func TestLockExpires(t *testing.T) {
	c := newClock()
	tr := New(testPolicy, c.now)
	failN(tr, "alice", "1.1.1.1", testPolicy.Threshold)
	c.advance(time.Minute + time.Second)
	if d := tr.Check("alice", "1.1.1.1"); d.Locked {
		t.Fatalf("lock did not expire: %+v", d)
	}
}

func TestStaleStateForgotten(t *testing.T) {
	c := newClock()
	tr := New(testPolicy, c.now)
	failN(tr, "alice", "1.1.1.1", testPolicy.Threshold-1)
	c.advance(testPolicy.FailWindow + time.Minute)
	// One more failure long after the window: counts restart, no lock.
	tr.Fail("alice", "1.1.1.1")
	if d := tr.Check("alice", "1.1.1.1"); d.Locked {
		t.Fatal("stale failures still counted after FailWindow")
	}
}

func TestChallengeHookFires(t *testing.T) {
	c := newClock()
	tr := New(testPolicy, c.now)
	var got []Dimension
	tr.ChallengeHook = func(dim Dimension, key string, level int) {
		got = append(got, dim)
	}
	failN(tr, "alice", "1.1.1.1", testPolicy.Threshold)
	if len(got) != 2 { // account + ip both lock at the same threshold here
		t.Fatalf("hook fired %d times, want 2", len(got))
	}
}

func TestConcurrentUse(t *testing.T) {
	tr := New(testPolicy, nil)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 100; i++ {
				tr.Fail("acct", "1.2.3.4")
				tr.Check("acct", "1.2.3.4")
				tr.Success("other", "5.6.7.8")
			}
		}(g)
	}
	wg.Wait()
	if d := tr.Check("acct", "1.2.3.4"); !d.Locked {
		t.Fatal("want locked after concurrent failures")
	}
}

// A credential-stuffing run walks a distinct username per attempt, all inside
// one FailWindow. Every entry is therefore young, so time-based expiry can
// reclaim nothing: only the size-triggered eviction bounds memory. Without it
// the attacker chooses how much RAM sentinel allocates.
func TestBurstOfDistinctKeysIsBounded(t *testing.T) {
	c := newClock()
	policy := testPolicy
	policy.MaxKeys = 512
	tr := New(policy, c.now)

	// Clock never advances: the burst arrives faster than FailWindow.
	for i := 0; i < 20*policy.MaxKeys; i++ {
		tr.Fail(fmt.Sprintf("drive-by-%d", i), "10.0.0.2")
	}

	tr.mu.Lock()
	accounts := len(tr.accounts)
	tr.mu.Unlock()

	if accounts > policy.MaxKeys {
		t.Errorf("accounts map held %d entries, over the %d cap", accounts, policy.MaxKeys)
	}
	// The attacker's own IP is few and stays tracked, which is the dimension
	// that actually stops the run.
	if d := tr.Check("someone", "10.0.0.2"); !d.Locked || d.Dimension != IP {
		t.Error("attacker IP should be locked out by the IP dimension")
	}
}

// Eviction must never release a lockout: that is the outcome an attacker would
// be buying by flooding the map. A locked victim survives a full cap-exceeding
// burst of unrelated usernames.
func TestEvictionNeverDropsALockedEntry(t *testing.T) {
	c := newClock()
	policy := testPolicy
	policy.MaxKeys = 64
	tr := New(policy, c.now)

	failN(tr, "victim", "10.0.0.1", policy.Threshold)
	if d := tr.Check("victim", "10.0.0.1"); !d.Locked {
		t.Fatal("victim should be locked after threshold failures")
	}

	for i := 0; i < 10*policy.MaxKeys; i++ {
		tr.Fail(fmt.Sprintf("filler-%d", i), "10.0.0.3")
	}

	if d := tr.Check("victim", "10.0.0.1"); !d.Locked || d.Dimension != Account {
		t.Error("victim lockout was evicted by a flood of unrelated usernames")
	}
}

// Stale entries are still reclaimed the moment time moves past FailWindow,
// so a quiet system does not hold yesterday's failure counters forever.
func TestSweepReclaimsStaleEntries(t *testing.T) {
	c := newClock()
	tr := New(testPolicy, c.now)

	tr.Fail("alice", "1.1.1.1") // one failure: counter only, no lock
	c.advance(testPolicy.FailWindow + time.Minute)

	tr.mu.Lock()
	tr.sweepStale(tr.accounts, c.now())
	n := len(tr.accounts)
	tr.mu.Unlock()

	if n != 0 {
		t.Errorf("stale account entry survived the sweep (%d left)", n)
	}
}

// A still-locked entry is older than FailWindow yet must not be swept: the
// lock outlives the failure-counting window it was born in.
func TestSweepKeepsStillLockedEntries(t *testing.T) {
	c := newClock()
	policy := Policy{
		Threshold:  3,
		BaseLock:   30 * time.Minute, // lock outlives FailWindow
		AccountCap: time.Hour,
		IPCap:      time.Hour,
		FailWindow: time.Minute,
	}
	tr := New(policy, c.now)

	failN(tr, "victim", "10.0.0.1", policy.Threshold)
	c.advance(policy.FailWindow + time.Second)

	tr.mu.Lock()
	tr.sweepStale(tr.accounts, c.now())
	_, kept := tr.accounts["victim"]
	tr.mu.Unlock()

	if !kept {
		t.Fatal("sweep dropped an account that is still locked out")
	}
	if d := tr.Check("victim", "9.9.9.9"); !d.Locked || d.Dimension != Account {
		t.Error("still-locked account stopped being locked after a sweep")
	}
}
