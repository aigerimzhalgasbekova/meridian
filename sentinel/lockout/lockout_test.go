package lockout

import (
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
	Threshold:  3,
	BaseLock:   time.Minute,
	AccountCap: 4 * time.Minute,
	IPCap:      time.Hour,
	FailWindow: time.Hour,
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
