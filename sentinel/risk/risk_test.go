package risk

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

var t0 = time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)

func newEngine(t *testing.T) *Engine {
	t.Helper()
	return New(Config{
		Geo:    TestFixture,
		BadIPs: []string{"233.252.0.66"},
	})
}

// establish gives alice a clean history: one successful login from Berlin
// on device d1 at t0.
func establish(e *Engine) {
	e.Observe(Attempt{Account: "alice", IP: "203.0.113.10", DeviceID: "d1", At: t0}, true)
}

func TestCleanAttemptAllows(t *testing.T) {
	e := newEngine(t)
	establish(e)
	as := e.Score(Attempt{Account: "alice", IP: "203.0.113.10", DeviceID: "d1", At: t0.Add(time.Hour)})
	if as.Score != 0 || as.Action != Allow || len(as.Reasons) != 0 {
		t.Fatalf("clean attempt scored %+v", as)
	}
}

func TestImpossibleTravel(t *testing.T) {
	e := newEngine(t)
	establish(e)
	cases := []struct {
		name    string
		ip      string
		elapsed time.Duration
		hit     bool
	}{
		{"berlin to tokyo in 10m", "198.51.100.5", 10 * time.Minute, true},
		{"berlin to tokyo in 24h", "198.51.100.5", 24 * time.Hour, false},
		{"berlin to paris in 2h", "203.0.113.20", 2 * time.Hour, false},
		{"unknown ip fails open", "10.9.9.9", time.Minute, false},
		{"same ip never travels", "203.0.113.10", time.Nanosecond, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			as := e.Score(Attempt{Account: "alice", IP: tc.ip, DeviceID: "d1", At: t0.Add(tc.elapsed)})
			got := hasReason(as, "impossible_travel")
			if got != tc.hit {
				t.Fatalf("impossible_travel = %v, want %v (%+v)", got, tc.hit, as)
			}
		})
	}
}

func TestNewDevice(t *testing.T) {
	e := newEngine(t)

	// First-ever device is enrollment, not anomaly.
	as := e.Score(Attempt{Account: "alice", IP: "203.0.113.10", DeviceID: "d1", At: t0})
	if hasReason(as, "new_device") {
		t.Fatalf("first device flagged: %+v", as)
	}
	establish(e)

	// Known device: clean. Unknown device: flagged. Missing fingerprint: flagged.
	for _, tc := range []struct {
		dev string
		hit bool
	}{{"d1", false}, {"d2", true}, {"", true}} {
		as := e.Score(Attempt{Account: "alice", IP: "203.0.113.10", DeviceID: tc.dev, At: t0.Add(time.Hour)})
		if hasReason(as, "new_device") != tc.hit {
			t.Fatalf("device %q: new_device = %v, want %v", tc.dev, !tc.hit, tc.hit)
		}
	}
}

func TestFailedAttemptDoesNotEnrollDevice(t *testing.T) {
	e := newEngine(t)
	establish(e)
	e.Observe(Attempt{Account: "alice", IP: "203.0.113.10", DeviceID: "evil", At: t0.Add(time.Minute)}, false)
	as := e.Score(Attempt{Account: "alice", IP: "203.0.113.10", DeviceID: "evil", At: t0.Add(2 * time.Minute)})
	if !hasReason(as, "new_device") {
		t.Fatal("failed attempt enrolled a device fingerprint")
	}
}

func TestVelocity(t *testing.T) {
	e := newEngine(t)
	establish(e)
	at := t0.Add(30 * time.Minute)
	for i := 0; i < 10; i++ {
		e.Observe(Attempt{Account: "alice", IP: "203.0.113.10", DeviceID: "d1", At: at}, false)
	}
	as := e.Score(Attempt{Account: "alice", IP: "203.0.113.10", DeviceID: "d1", At: at.Add(time.Second)})
	if !hasReason(as, "velocity") {
		t.Fatalf("10 rapid attempts not flagged: %+v", as)
	}
	// Outside the window the burst is forgotten.
	as = e.Score(Attempt{Account: "alice", IP: "203.0.113.10", DeviceID: "d1", At: at.Add(6 * time.Minute)})
	if hasReason(as, "velocity") {
		t.Fatalf("stale burst still flagged: %+v", as)
	}
}

func TestKnownBadIPDenies(t *testing.T) {
	e := newEngine(t)
	establish(e)
	as := e.Score(Attempt{Account: "alice", IP: "233.252.0.66", DeviceID: "d1", At: t0.Add(time.Hour)})
	if !hasReason(as, "known_bad_ip") || as.Action != Deny {
		t.Fatalf("bad IP not denied: %+v", as)
	}
}

func TestScoreClampsAndThresholds(t *testing.T) {
	e := newEngine(t)
	establish(e)
	// Bad IP (60) + new device (20) + travel (45) must clamp at 100.
	at := t0.Add(time.Minute)
	e.Observe(Attempt{Account: "alice", IP: "203.0.113.10", DeviceID: "d1", At: at}, true)
	as := e.Score(Attempt{Account: "alice", IP: "233.252.0.66", DeviceID: "d9", At: at.Add(time.Second)})
	if as.Score > 100 {
		t.Fatalf("score %d exceeds 100", as.Score)
	}
	if as.Action != Deny {
		t.Fatalf("action = %s, want deny (%+v)", as.Action, as)
	}
}

func TestStepUpBand(t *testing.T) {
	e := newEngine(t)
	establish(e)
	// New device alone (20 points) allows; travel alone (45) steps up.
	as := e.Score(Attempt{Account: "alice", IP: "203.0.113.10", DeviceID: "d2", At: t0.Add(time.Hour)})
	if as.Action != Allow {
		t.Fatalf("20 points: action = %s, want allow", as.Action)
	}
	as = e.Score(Attempt{Account: "alice", IP: "198.51.100.5", DeviceID: "d1", At: t0.Add(10 * time.Minute)})
	if as.Action != StepUp {
		t.Fatalf("45 points: action = %s, want step_up (%+v)", as.Action, as)
	}
}

func TestScoreIsDeterministicAndPure(t *testing.T) {
	e := newEngine(t)
	establish(e)
	a := Attempt{Account: "alice", IP: "198.51.100.5", DeviceID: "d2", At: t0.Add(time.Minute)}
	first := e.Score(a)
	for i := 0; i < 5; i++ {
		if got := e.Score(a); got.Score != first.Score || got.Action != first.Action {
			t.Fatalf("Score mutated state: run %d got %+v, want %+v", i, got, first)
		}
	}
}

func TestUnknownAccountIsCleanish(t *testing.T) {
	e := newEngine(t)
	as := e.Score(Attempt{Account: "nobody", IP: "203.0.113.10", DeviceID: "", At: t0})
	if as.Action == Deny {
		t.Fatalf("cold-start attempt denied: %+v", as)
	}
}

func TestConcurrentScoreObserve(t *testing.T) {
	e := newEngine(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				at := t0.Add(time.Duration(j) * time.Second)
				e.Observe(Attempt{Account: "alice", IP: "203.0.113.10", DeviceID: "d1", At: at}, j%2 == 0)
				e.Score(Attempt{Account: "alice", IP: "198.51.100.5", DeviceID: "d1", At: at})
			}
		}(i)
	}
	wg.Wait()
}

func TestHaversine(t *testing.T) {
	// Berlin → Paris is ~878 km.
	km := haversineKM(52.52, 13.405, 48.8566, 2.3522)
	if km < 850 || km > 900 {
		t.Fatalf("Berlin→Paris = %.0f km, want ~878", km)
	}
	if d := haversineKM(52.52, 13.405, 52.52, 13.405); d != 0 {
		t.Fatalf("zero distance = %f", d)
	}
}

func hasReason(as Assessment, signal string) bool {
	for _, r := range as.Reasons {
		if r.Signal == signal {
			return true
		}
	}
	return false
}

// Guard against reason text regressions the compliance report keys on.
func TestReasonDetailsPresent(t *testing.T) {
	e := newEngine(t)
	establish(e)
	as := e.Score(Attempt{Account: "alice", IP: "198.51.100.5", DeviceID: "d2", At: t0.Add(time.Minute)})
	for _, r := range as.Reasons {
		if strings.TrimSpace(r.Detail) == "" {
			t.Fatalf("signal %s has empty detail", r.Signal)
		}
	}
}

// TestAccountMapIsBounded pins the OOM defense: account names come straight
// from login forms, so a stuffing run walking fresh usernames must not grow
// the engine without limit. Sentinel also holds the rate-limit windows and
// lockout state — an OOM-kill would hand the attacker a clean slate.
func TestAccountMapIsBounded(t *testing.T) {
	e := New(Config{MaxAccounts: 100, Geo: nil})
	now := time.Date(2026, 7, 9, 12, 0, 0, 0, time.UTC)
	for i := range 10_000 {
		e.Observe(Attempt{Account: fmt.Sprintf("victim-%d", i), IP: "203.0.113.9", At: now}, false)
	}
	e.mu.Lock()
	n := len(e.accounts)
	e.mu.Unlock()
	if n > 100 {
		t.Fatalf("tracking %d accounts, cap is 100", n)
	}

	// A real account with a device baseline survives a burst of junk: the
	// bound must not become a way to evict the signal history that matters.
	e2 := New(Config{MaxAccounts: 100})
	e2.Observe(Attempt{Account: "real", IP: "198.51.100.4", DeviceID: "dev-1", At: now}, true)
	for i := range 1_000 {
		e2.Observe(Attempt{Account: fmt.Sprintf("junk-%d", i), IP: "203.0.113.9", At: now}, false)
	}
	e2.mu.Lock()
	h, ok := e2.accounts["real"]
	trusted := ok && h.Devices["dev-1"]
	e2.mu.Unlock()
	if !trusted {
		t.Error("eviction dropped an account with a trusted-device baseline first")
	}
}
