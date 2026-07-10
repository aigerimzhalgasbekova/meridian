package auth

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestHS256RoundTrip(t *testing.T) {
	h := HS256{Key: []byte("k")}
	sub, err := h.Verify(h.Mint("alice", time.Minute))
	if err != nil || sub != "alice" {
		t.Fatalf("Verify(minted) = %q, %v", sub, err)
	}
}

func TestHS256Rejects(t *testing.T) {
	h := HS256{Key: []byte("k")}
	good := h.Mint("alice", time.Minute)
	parts := strings.Split(good, ".")

	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	noneToken := enc(map[string]string{"alg": "none"}) + "." + parts[1] + "."
	algSwap := enc(map[string]string{"alg": "RS256"}) + "." + parts[1] + "." + parts[2]
	expired := HS256{Key: []byte("k"), Now: func() time.Time { return time.Now().Add(-time.Hour) }}.Mint("alice", time.Minute)
	noSub := func() string {
		input := enc(map[string]string{"alg": "HS256"}) + "." + enc(map[string]any{"exp": time.Now().Add(time.Minute).Unix()})
		return input + "." + base64.RawURLEncoding.EncodeToString(h.sign(input))
	}()

	tests := []struct {
		name, token string
	}{
		{"empty", ""},
		{"two parts", parts[0] + "." + parts[1]},
		{"garbage", "a.b.c"},
		{"alg none", noneToken},
		{"alg swapped", algSwap},
		{"wrong key", HS256{Key: []byte("other")}.Mint("alice", time.Minute)},
		{"tampered payload", parts[0] + "." + enc(map[string]any{"sub": "root", "exp": time.Now().Add(time.Hour).Unix()}) + "." + parts[2]},
		{"expired", expired},
		{"missing sub", noSub},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if sub, err := h.Verify(tt.token); err == nil {
				t.Errorf("Verify accepted %s token as %q", tt.name, sub)
			}
		})
	}
}
