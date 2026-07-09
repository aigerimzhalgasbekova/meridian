package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestParseScopesDedupesPreservingOrder(t *testing.T) {
	got := ParseScopes("openid profile openid email profile")
	want := Scopes{"openid", "profile", "email"}
	if got.String() != want.String() {
		t.Errorf("got %v, want %v", got, want)
	}
	if ParseScopes("") != nil {
		t.Error("empty scope should be nil")
	}
	if ParseScopes("   ") != nil {
		t.Error("whitespace scope should be nil")
	}
}

func TestScopeSetOps(t *testing.T) {
	s := Scopes{"a", "b", "c"}
	if got := s.Subtract(Scopes{"b"}); got.String() != "a c" {
		t.Errorf("Subtract: %v", got)
	}
	if got := s.Intersect(Scopes{"c", "a", "z"}); got.String() != "a c" {
		t.Errorf("Intersect: %v", got)
	}
	if !s.Has("b") || s.Has("z") {
		t.Error("Has")
	}
}

func TestValidCodeChallenge(t *testing.T) {
	sum := sha256.Sum256([]byte("verifier"))
	valid := base64.RawURLEncoding.EncodeToString(sum[:])
	if !ValidCodeChallenge(valid) {
		t.Error("valid S256 challenge rejected")
	}
	for _, bad := range []string{"", "short", valid + "extra", "!!!!" + valid[4:]} {
		if ValidCodeChallenge(bad) {
			t.Errorf("accepted bad challenge %q", bad)
		}
	}
}

func TestVerifyPKCE(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	if !VerifyPKCE(challenge, verifier) {
		t.Error("valid PKCE pair rejected")
	}
	if VerifyPKCE(challenge, "wrong-verifier-that-is-long-enough-to-pass-regex-checks") {
		t.Error("wrong verifier accepted")
	}
	if VerifyPKCE("", verifier) {
		t.Error("empty challenge accepted")
	}
	if VerifyPKCE(challenge, "short") {
		t.Error("too-short verifier accepted")
	}
	if VerifyPKCE(challenge, verifier+"\x00bad chars!") {
		t.Error("verifier with illegal chars accepted")
	}
}

func TestRedirectErrorStaysOnClient(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/authorize", nil)
	ru := mustURL(t, "https://client.example/cb?existing=1")
	RedirectError(w, r, ru, E(ErrAccessDenied, "denied"), "state123")
	loc := w.Header().Get("Location")
	u := mustURL(t, loc)
	if u.Host != "client.example" {
		t.Fatalf("redirected off-client: %s", loc)
	}
	q := u.Query()
	if q.Get("error") != "access_denied" || q.Get("state") != "state123" || q.Get("existing") != "1" {
		t.Errorf("bad redirect query: %s", loc)
	}
}

func TestTokenErrorStatusCodes(t *testing.T) {
	cases := map[ErrorCode]int{
		ErrInvalidClient:          401,
		ErrInvalidGrant:           400,
		ErrInvalidRequest:         400,
		ErrServerError:            500,
		ErrTemporarilyUnavailable: 503,
	}
	for code, want := range cases {
		w := httptest.NewRecorder()
		WriteTokenError(w, E(code, "x"), false)
		if w.Code != want {
			t.Errorf("%s: status %d, want %d", code, w.Code, want)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: missing no-store", code)
		}
	}
	// invalid_client with Basic attempt carries a challenge.
	w := httptest.NewRecorder()
	WriteTokenError(w, E(ErrInvalidClient, "x"), true)
	if w.Header().Get("WWW-Authenticate") == "" {
		t.Error("no WWW-Authenticate on Basic invalid_client")
	}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
