package server

import (
	"net/http/httptest"
	"testing"
)

// The brute-force guard keys on remoteIP. If a client could choose that key it
// could get a fresh lockout bucket per request, so these cases pin exactly when
// X-Forwarded-For is honored and which hop is read.
func TestRemoteIP(t *testing.T) {
	const peer = "203.0.113.9"

	tests := []struct {
		name       string
		xff        string
		trustProxy bool
		want       string
	}{
		{
			name: "no header falls back to the socket peer",
			want: peer,
		},
		{
			name: "forged header is ignored when no proxy is trusted",
			xff:  "1.2.3.4",
			want: peer,
		},
		{
			name:       "trusted proxy: sole hop is the observed client",
			xff:        "198.51.100.7",
			trustProxy: true,
			want:       "198.51.100.7",
		},
		{
			name: "trusted proxy: last hop wins, client-supplied prefix ignored",
			// The client sent "1.2.3.4"; the proxy appended what it saw.
			// Reading the first hop here would let the client pick its key.
			xff:        "1.2.3.4, 198.51.100.7",
			trustProxy: true,
			want:       "198.51.100.7",
		},
		{
			name:       "trusted proxy: surrounding whitespace trimmed",
			xff:        "1.2.3.4,   198.51.100.7  ",
			trustProxy: true,
			want:       "198.51.100.7",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/realms/demo/login", nil)
			r.RemoteAddr = peer + ":54321"
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if got := remoteIP(r, tc.trustProxy); got != tc.want {
				t.Errorf("remoteIP() = %q, want %q", got, tc.want)
			}
		})
	}
}
