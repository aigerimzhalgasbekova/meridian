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
	got, err := m.Consume(state, "google")
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
	_, state, _ := m.Begin("google", ModeLogin, "", "")

	tests := []struct {
		name  string
		state string
		prov  string
		want  error
		prep  func()
	}{
		{"garbage", "not-a-state", "google", ErrBadState, nil},
		{"no signature", strings.Split(state, ".")[0], "google", ErrBadState, nil},
		{"tampered signature", strings.Split(state, ".")[0] + ".AAAA", "google", ErrBadState, nil},
		{"wrong provider", state, "entra", ErrBadState, nil},
		{"replay", state, "google", ErrStateUsed, func() {
			if _, err := m.Consume(state, "google"); err != nil {
				t.Fatalf("first consume must succeed: %v", err)
			}
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.prep != nil {
				tt.prep()
			}
			_, err := m.Consume(tt.state, tt.prov)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v, want %v", err, tt.want)
			}
		})
	}

	t.Run("expired", func(t *testing.T) {
		_, state, _ := m.Begin("google", ModeLogin, "", "")
		clock = clock.Add(TTL + time.Second)
		if _, err := m.Consume(state, "google"); !errors.Is(err, ErrStateExpired) {
			t.Fatalf("got %v, want ErrStateExpired", err)
		}
	})

	t.Run("forged by other key", func(t *testing.T) {
		other, err := NewManager([]byte("ffffffffffffffffffffffffffffffff"), nil)
		if err != nil {
			t.Fatal(err)
		}
		_, forged, _ := other.Begin("google", ModeLogin, "", "")
		if _, err := m.Consume(forged, "google"); !errors.Is(err, ErrBadState) {
			t.Fatalf("got %v, want ErrBadState", err)
		}
	})
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
