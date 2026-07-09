package server_test

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// redirectErr fetches the authorize URL and asserts an error redirect back to
// the client with the given code.
func redirectErr(t *testing.T, e *env, params map[string]string, wantErr string) {
	t.Helper()
	resp, body := e.get(authorizeURL(params))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d (want 302 redirect): %s", resp.StatusCode, body)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(loc.String(), "https://app.example/callback") &&
		!strings.HasPrefix(loc.String(), "https://spa.example/callback") {
		t.Fatalf("error redirected off-client: %s", loc)
	}
	if got := loc.Query().Get("error"); got != wantErr {
		t.Errorf("error = %q, want %q (desc: %s)", got, wantErr, loc.Query().Get("error_description"))
	}
	if st := loc.Query().Get("state"); st != params["state"] {
		t.Errorf("state not echoed: %q", st)
	}
}

// pageErr asserts the request dies on an error page with NO redirect.
func pageErr(t *testing.T, e *env, params map[string]string) {
	t.Helper()
	resp, _ := e.get(authorizeURL(params))
	if resp.StatusCode == http.StatusFound {
		t.Fatalf("redirected (Location: %s) — must render an error page instead", resp.Header.Get("Location"))
	}
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status %d, want 400", resp.StatusCode)
	}
}

func TestAuthorizeValidation(t *testing.T) {
	base := func(over map[string]string) map[string]string {
		m := map[string]string{
			"client_id":     "web-app",
			"redirect_uri":  "https://app.example/callback",
			"response_type": "code",
			"scope":         "openid",
			"state":         "xyz",
		}
		for k, v := range over {
			if v == "-" {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return m
	}

	t.Run("unknown client renders page not redirect", func(t *testing.T) {
		pageErr(t, newEnv(t), base(map[string]string{"client_id": "ghost"}))
	})
	t.Run("unregistered redirect_uri renders page not redirect", func(t *testing.T) {
		pageErr(t, newEnv(t), base(map[string]string{"redirect_uri": "https://evil.example/steal"}))
	})
	t.Run("redirect_uri with extra path renders page (exact match)", func(t *testing.T) {
		pageErr(t, newEnv(t), base(map[string]string{"redirect_uri": "https://app.example/callback/../admin"}))
	})
	t.Run("missing redirect_uri with one registered defaults", func(t *testing.T) {
		e := newEnv(t)
		resp, body := e.get(authorizeURL(base(map[string]string{"redirect_uri": "-"})))
		if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Sign in") {
			t.Fatalf("expected login page, got %d", resp.StatusCode)
		}
	})
	t.Run("unsupported response_type redirects error", func(t *testing.T) {
		redirectErr(t, newEnv(t), base(map[string]string{"response_type": "token"}), "unsupported_response_type")
	})
	t.Run("implicit hybrid rejected", func(t *testing.T) {
		redirectErr(t, newEnv(t), base(map[string]string{"response_type": "code id_token"}), "unsupported_response_type")
	})
	t.Run("scope not allowed for client", func(t *testing.T) {
		redirectErr(t, newEnv(t), base(map[string]string{"scope": "openid inventory:read"}), "invalid_scope")
	})
	t.Run("public client without PKCE rejected", func(t *testing.T) {
		redirectErr(t, newEnv(t), map[string]string{
			"client_id":     "spa",
			"redirect_uri":  "https://spa.example/callback",
			"response_type": "code",
			"scope":         "openid",
			"state":         "xyz",
		}, "invalid_request")
	})
	t.Run("plain PKCE method rejected", func(t *testing.T) {
		_, challenge := pkcePair()
		redirectErr(t, newEnv(t), base(map[string]string{
			"code_challenge":        challenge,
			"code_challenge_method": "plain",
		}), "invalid_request")
	})
	t.Run("malformed code_challenge rejected", func(t *testing.T) {
		redirectErr(t, newEnv(t), base(map[string]string{
			"code_challenge":        "tooshort",
			"code_challenge_method": "S256",
		}), "invalid_request")
	})
	t.Run("prompt=none without session yields login_required", func(t *testing.T) {
		redirectErr(t, newEnv(t), base(map[string]string{"prompt": "none"}), "login_required")
	})
	t.Run("client without authorization_code grant", func(t *testing.T) {
		e := newEnv(t)
		// "service" has only client_credentials; give it a redirect check bypass:
		// unknown redirect → page error is fine, but we want unauthorized_client,
		// so hit it with no redirect_uri registered → page error acceptable per
		// our order. Use cli client with registered redirect? cli has none.
		// The check order (client → redirect → grant) means this renders a page.
		resp, _ := e.get(authorizeURL(map[string]string{
			"client_id":     "service",
			"response_type": "code",
			"scope":         "inventory:read",
		}))
		if resp.StatusCode == http.StatusFound {
			t.Fatal("must not redirect for a client with no registered redirect URIs")
		}
	})
}

func TestAuthorizeFullFlowWithConsent(t *testing.T) {
	e := newEnv(t)
	code := e.obtainCode(nil) // web-app is NOT first-party: consent shown
	if !strings.HasPrefix(code, "ac_") {
		t.Errorf("unexpected code shape: %q", code)
	}

	// Second authorization with same scopes: consent is remembered, and the
	// session is still live — straight to code.
	resp, _ := e.get(authorizeURL(map[string]string{
		"client_id":     "web-app",
		"redirect_uri":  "https://app.example/callback",
		"response_type": "code",
		"scope":         "openid profile email offline_access",
		"state":         "second",
	}))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("re-authorization should skip login+consent, got %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Fatalf("no code on silent re-auth: %s", loc)
	}
}

func TestAuthorizeFirstPartySkipsConsent(t *testing.T) {
	e := newEnv(t)
	// Login via the portal client (first-party).
	resp, body := e.get(authorizeURL(map[string]string{
		"client_id":     "portal",
		"redirect_uri":  "https://portal.example/callback",
		"response_type": "code",
		"scope":         "openid profile",
		"state":         "fp",
	}))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected login page, got %d", resp.StatusCode)
	}
	resp, body = e.login(body, "alice", testUserPassword)
	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login failed: %d %s", resp.StatusCode, body)
	}
	resp, body = e.get(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("first-party flow should go straight to code after login, got %d: %s", resp.StatusCode, body)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("code") == "" {
		t.Fatalf("no code: %s", loc)
	}
}

func TestConsentDenyRedirectsAccessDenied(t *testing.T) {
	e := newEnv(t)
	resp, body := e.get(authorizeURL(map[string]string{
		"client_id":     "web-app",
		"redirect_uri":  "https://app.example/callback",
		"response_type": "code",
		"scope":         "openid",
		"state":         "denied",
	}))
	resp, body = e.login(body, "alice", testUserPassword)
	resp, body = e.get(resp.Header.Get("Location"))
	if !strings.Contains(body, "requests access") {
		t.Fatalf("expected consent page: %s", body)
	}
	resp, _ = e.consent(body, "deny")
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("deny should redirect to client, got %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Query().Get("error") != "access_denied" || loc.Query().Get("state") != "denied" {
		t.Errorf("deny redirect: %s", loc)
	}
}

func TestLoginSecurity(t *testing.T) {
	t.Run("wrong password stays on login with uniform error", func(t *testing.T) {
		e := newEnv(t)
		_, body := e.get(authorizeURL(map[string]string{
			"client_id": "web-app", "redirect_uri": "https://app.example/callback",
			"response_type": "code", "scope": "openid", "state": "x",
		}))
		resp, body2 := e.login(body, "alice", "wrong-password")
		if resp.StatusCode != http.StatusOK || !strings.Contains(body2, "Incorrect username or password") {
			t.Fatalf("unexpected: %d %s", resp.StatusCode, body2)
		}
	})
	t.Run("unknown user gets identical error", func(t *testing.T) {
		e := newEnv(t)
		_, body := e.get(authorizeURL(map[string]string{
			"client_id": "web-app", "redirect_uri": "https://app.example/callback",
			"response_type": "code", "scope": "openid", "state": "x",
		}))
		resp, body2 := e.login(body, "who-is-this", "whatever-pass")
		if resp.StatusCode != http.StatusOK || !strings.Contains(body2, "Incorrect username or password") {
			t.Fatalf("unexpected: %d %s", resp.StatusCode, body2)
		}
	})
	t.Run("brute force lockout after 10 failures", func(t *testing.T) {
		e := newEnv(t)
		_, body := e.get(authorizeURL(map[string]string{
			"client_id": "web-app", "redirect_uri": "https://app.example/callback",
			"response_type": "code", "scope": "openid", "state": "x",
		}))
		for range 10 {
			_, body = e.login(body, "alice", "wrong-password")
		}
		_, body = e.login(body, "alice", testUserPassword) // correct now — but locked
		if !strings.Contains(body, "Too many attempts") {
			t.Fatalf("expected lockout, got: %s", firstLine(body))
		}
		// Window passes → allowed again.
		e.clock.Advance(16 * time.Minute)
		resp, _ := e.login(body, "alice", testUserPassword)
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("lockout did not expire: %d", resp.StatusCode)
		}
	})
	t.Run("csrf token required", func(t *testing.T) {
		e := newEnv(t)
		_, body := e.get(authorizeURL(map[string]string{
			"client_id": "web-app", "redirect_uri": "https://app.example/callback",
			"response_type": "code", "scope": "openid", "state": "x",
		}))
		ret := returnToRe.FindStringSubmatch(body)
		resp, body2 := e.postForm("/realms/test/login", url.Values{
			"csrf_token": {"forged-token"},
			"return_to":  {ret[1]},
			"username":   {"alice"},
			"password":   {testUserPassword},
		})
		if resp.StatusCode == http.StatusSeeOther {
			t.Fatal("login succeeded with forged CSRF token")
		}
		_ = body2
	})
	t.Run("return_to must stay on realm authorize", func(t *testing.T) {
		e := newEnv(t)
		_, body := e.get(authorizeURL(map[string]string{
			"client_id": "web-app", "redirect_uri": "https://app.example/callback",
			"response_type": "code", "scope": "openid", "state": "x",
		}))
		csrf := csrfRe.FindStringSubmatch(body)
		for _, evil := range []string{
			"https://evil.example/phish",
			"//evil.example/phish",
			"/realms/other/authorize?client_id=web-app",
			"/logout",
		} {
			resp, _ := e.postForm("/realms/test/login", url.Values{
				"csrf_token": {csrf[1]},
				"return_to":  {evil},
				"username":   {"alice"},
				"password":   {testUserPassword},
			})
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("return_to %q: status %d, want 400", evil, resp.StatusCode)
			}
		}
	})
}

func TestSessionFixationDefense(t *testing.T) {
	e := newEnv(t)
	// Plant a cookie before login; after login the session must differ.
	u, _ := url.Parse(e.idp.URL)
	e.client.Jar.SetCookies(u, []*http.Cookie{{
		Name: "idp_session_test", Value: "sid_planted", Path: "/realms/test",
	}})
	_ = e.obtainCode(nil)
	for _, c := range e.client.Jar.Cookies(u) {
		if c.Name == "idp_session_test" && c.Value == "sid_planted" {
			t.Fatal("session ID survived login — fixation possible")
		}
	}
}

func TestMaxAgeForcesReauth(t *testing.T) {
	e := newEnv(t)
	_ = e.obtainCode(nil) // session established
	e.clock.Advance(2 * time.Hour)
	resp, body := e.get(authorizeURL(map[string]string{
		"client_id": "web-app", "redirect_uri": "https://app.example/callback",
		"response_type": "code", "scope": "openid", "state": "x",
		"max_age": "3600", // authenticated 2h ago > 1h
	}))
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Sign in") {
		t.Fatalf("expected re-login, got %d", resp.StatusCode)
	}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i > 0 {
		return s[:i]
	}
	return s
}
