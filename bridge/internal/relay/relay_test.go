package relay

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func testManager(t *testing.T, now func() time.Time) *Manager {
	t.Helper()
	m, err := NewManager([]byte("0123456789abcdef0123456789abcdef"), now)
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
		other, err := NewManager([]byte("ffffffffffffffffffffffffffffffff"), nil)
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

// /login/{provider} is unauthenticated: a flood must be shed, not absorbed.
func TestFlowTableIsCapped(t *testing.T) {
	m := testManager(t, nil)
	for i := 0; i < maxFlows; i++ {
		m.flows[randomToken()] = Flow{Expires: time.Now().Add(TTL)}
	}
	if _, _, err := m.Begin("google", ModeLogin, "", ""); !errors.Is(err, ErrTooBusy) {
		t.Fatalf("full flow table accepted another flow: %v", err)
	}
	// Expire the whole backlog. Capacity must NOT come back yet: the sweep is
	// throttled, which is what stops each request costing O(live flows) under
	// the manager's mutex.
	m.mu.Lock()
	for id, f := range m.flows {
		f.Expires = time.Now().Add(-time.Hour)
		m.flows[id] = f
	}
	m.mu.Unlock()
	if _, _, err := m.Begin("google", ModeLogin, "", ""); !errors.Is(err, ErrTooBusy) {
		t.Fatalf("sweep ran before it was due: %v", err)
	}
	m.mu.Lock()
	m.lastSweep = time.Now().Add(-sweepInterval)
	m.mu.Unlock()
	if _, _, err := m.Begin("google", ModeLogin, "", ""); err != nil {
		t.Fatalf("due sweep did not free capacity: %v", err)
	}
}

func TestChallenge(t *testing.T) {
	// RFC 7636 appendix B test vector.
	if got := Challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("Challenge = %q", got)
	}
}

func TestShortKeyRejected(t *testing.T) {
	if _, err := NewManager([]byte("short"), nil); err == nil {
		t.Fatal("short HMAC key accepted")
	}
}
