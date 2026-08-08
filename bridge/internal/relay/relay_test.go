package relay

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func testManager(t *testing.T, now func() time.Time) *Manager {
	t.Helper()
	m, err := NewManager([]byte("0123456789abcdef0123456789abcdef"), now, nil)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestFlowRoundTrip(t *testing.T) {
	m := testManager(t, nil)
	f, state, err := m.Begin("google", ModeLogin, "app1", "")
	if err != nil {
		t.Fatal(err)
	}
	if f.Nonce == "" || f.Verifier == "" || len(f.Verifier) != 43 {
		t.Fatalf("flow missing nonce/verifier: %+v", f)
	}
	if f.Binding == "" || f.Binding == f.ID || f.Binding == f.Nonce {
		t.Fatalf("binding must be its own secret: %+v", f)
	}
	got, err := m.Consume(state, "google", f.Binding)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != f.ID || got.Nonce != f.Nonce || got.Verifier != f.Verifier || got.AppID != "app1" {
		t.Fatalf("consumed flow does not match: %+v vs %+v", got, f)
	}
}

func TestConsumeRejects(t *testing.T) {
	clock := time.Now()
	m := testManager(t, func() time.Time { return clock })
	f, state, _ := m.Begin("google", ModeLogin, "", "")

	tests := []struct {
		name    string
		state   string
		prov    string
		binding string
		want    error
		prep    func()
	}{
		{"garbage", "not-a-state", "google", f.Binding, ErrBadState, nil},
		{"no signature", strings.Split(state, ".")[0], "google", f.Binding, ErrBadState, nil},
		{"tampered signature", strings.Split(state, ".")[0] + ".AAAA", "google", f.Binding, ErrBadState, nil},
		{"wrong provider", state, "entra", f.Binding, ErrBadState, nil},
		{"replay", state, "google", f.Binding, ErrStateUsed, func() {
			if _, err := m.Consume(state, "google", f.Binding); err != nil {
				t.Fatalf("first consume must succeed: %v", err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.prep != nil {
				tt.prep()
			}
			_, err := m.Consume(tt.state, tt.prov, tt.binding)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}

	t.Run("expired", func(t *testing.T) {
		f, state, _ := m.Begin("google", ModeLogin, "", "")
		clock = clock.Add(TTL + time.Second)
		if _, err := m.Consume(state, "google", f.Binding); !errors.Is(err, ErrStateExpired) {
			t.Fatalf("got %v, want ErrStateExpired", err)
		}
	})

	t.Run("forged by other key", func(t *testing.T) {
		other, err := NewManager([]byte("ffffffffffffffffffffffffffffffff"), nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		f, forged, _ := other.Begin("google", ModeLogin, "", "")
		if _, err := m.Consume(forged, "google", f.Binding); !errors.Is(err, ErrBadState) {
			t.Fatalf("got %v, want ErrBadState", err)
		}
	})
}

// The whole point of the binding: a genuine, unexpired, never-used state is
// still refused when the presenting browser does not hold the cookie. An
// absent cookie arrives as "" and must fail exactly like a wrong one — and
// either way the flow is burned, so a failed hijack is not a retry loop
// against still-live state.
func TestConsumeRequiresBrowserBinding(t *testing.T) {
	for _, binding := range []string{"", randomToken()} {
		m := testManager(t, nil)
		f, state, err := m.Begin("google", ModeLogin, "", "")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := m.Consume(state, "google", binding); !errors.Is(err, ErrUnbound) {
			t.Fatalf("binding %q: got %v, want ErrUnbound", binding, err)
		}
		if _, err := m.Consume(state, "google", f.Binding); !errors.Is(err, ErrStateUsed) {
			t.Fatalf("binding %q: flow survived a failed binding check: %v", binding, err)
		}
	}
}

// /login/{provider} is unauthenticated: a flood must be bounded in memory, and
// it must not cost everyone else their login. A table filled with live flows
// still admits the next one — by evicting, not by refusing.
func TestFullFlowTableEvictsInsteadOfRefusing(t *testing.T) {
	m := testManager(t, nil)
	for i := 0; i < maxFlows; i++ {
		m.flows[randomToken()] = Flow{Expires: time.Now().Add(TTL)}
	}
	f, state, err := m.Begin("google", ModeLogin, "", "")
	if err != nil {
		t.Fatalf("full flow table refused a legitimate login: %v", err)
	}
	if len(m.flows) != maxFlows {
		t.Fatalf("table size = %d, want the cap %d", len(m.flows), maxFlows)
	}
	if got, err := m.Consume(state, "google", f.Binding); err != nil || got.ID != f.ID {
		t.Fatalf("the admitted flow must be usable: %v", err)
	}
}

// The sweep is now the *only* thing that reclaims abandoned flows: eviction
// hides a dead sweep, because a table stuck at maxFlows keeps admitting logins
// while never releasing 10-minute-expired garbage. Pin the reclamation itself.
func TestExpiredFlowsAreSwept(t *testing.T) {
	clock := time.Now()
	m := testManager(t, func() time.Time { return clock })
	for i := 0; i < 10; i++ {
		m.flows[randomToken()] = Flow{Expires: clock.Add(TTL)}
	}
	clock = clock.Add(TTL + sweepInterval)
	if _, _, err := m.Begin("google", ModeLogin, "", ""); err != nil {
		t.Fatal(err)
	}
	if len(m.flows) != 1 {
		t.Fatalf("due sweep did not reclaim expired flows: %d left, want only the new one", len(m.flows))
	}
}

// An evicted flow's callback fails as ErrStateUsed and logs "possible replay",
// so saturation must announce itself or an operator cannot tell a full table
// from an attack.
func TestSaturationIsLogged(t *testing.T) {
	// Through the *configured* logger, not slog.Default(): a service that wires
	// its own handler must still see this.
	var buf bytes.Buffer
	clock := time.Now()
	m, err := NewManager([]byte("0123456789abcdef0123456789abcdef"),
		func() time.Time { return clock }, slog.New(slog.NewTextHandler(&buf, nil)))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxFlows; i++ {
		m.flows[randomToken()] = Flow{Expires: clock.Add(TTL)}
	}
	if _, _, err := m.Begin("google", ModeLogin, "", ""); err != nil { // evicts
		t.Fatal(err)
	}
	clock = clock.Add(sweepInterval) // next sweep tick drains the counter
	if _, _, err := m.Begin("google", ModeLogin, "", ""); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "flow table saturated") {
		t.Fatalf("eviction produced no operator signal: %q", buf.String())
	}
}

func TestChallenge(t *testing.T) {
	// RFC 7636 appendix B test vector.
	if got := Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("Challenge = %q", got)
	}
}

func TestShortKeyRejected(t *testing.T) {
	if _, err := NewManager([]byte("short"), nil, nil); err == nil {
		t.Fatal("short HMAC key accepted")
	}
}
