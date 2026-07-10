package server_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// TestOversizedFormBodyRejected guards the body-size cap on form endpoints.
// Without it, r.ParseForm reads an unbounded body into memory — an
// unauthenticated memory-exhaustion DoS. The handler must fail closed (400),
// not swallow a multi-megabyte body.
func TestOversizedFormBodyRejected(t *testing.T) {
	e := newEnv(t)
	// ~2 MiB of form payload, past the 1 MiB cap.
	huge := strings.Repeat("a", 2<<20)
	form := url.Values{"grant_type": {"authorization_code"}, "code": {huge}}

	resp, _ := e.postForm("/realms/test/token", form)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("oversized body: got status %d, want 400", resp.StatusCode)
	}
}
