package server_test

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTokenClientAuthentication(t *testing.T) {
	grant := url.Values{"grant_type": {"client_credentials"}, "scope": {"inventory:read"}}

	t.Run("basic auth happy path", func(t *testing.T) {
		e := newEnv(t)
		status, body := e.tokenRequest("service", webAppSecret, grant)
		if status != http.StatusOK || str(body, "access_token") == "" {
			t.Fatalf("%d: %v", status, body)
		}
	})
	t.Run("form post auth happy path", func(t *testing.T) {
		e := newEnv(t)
		status, body := e.tokenRequest("", "", url.Values{
			"grant_type": {"client_credentials"}, "scope": {"inventory:read"},
			"client_id": {"service"}, "client_secret": {webAppSecret},
		})
		if status != http.StatusOK || str(body, "access_token") == "" {
			t.Fatalf("%d: %v", status, body)
		}
	})
	t.Run("wrong secret is 401 invalid_client with challenge", func(t *testing.T) {
		e := newEnv(t)
		req, _ := http.NewRequest("POST", e.idp.URL+"/realms/test/token", strings.NewReader(grant.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("service", "wrong-secret")
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status %d, want 401", resp.StatusCode)
		}
		if !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Basic") {
			t.Errorf("missing WWW-Authenticate challenge on Basic attempt")
		}
	})
	t.Run("unknown client is invalid_client", func(t *testing.T) {
		e := newEnv(t)
		status, body := e.tokenRequest("ghost", "whatever", grant)
		if status != http.StatusUnauthorized || str(body, "error") != "invalid_client" {
			t.Fatalf("%d: %v", status, body)
		}
	})
	t.Run("no credentials is invalid_client", func(t *testing.T) {
		e := newEnv(t)
		status, body := e.tokenRequest("", "", grant)
		if status != http.StatusUnauthorized || str(body, "error") != "invalid_client" {
			t.Fatalf("%d: %v", status, body)
		}
	})
	t.Run("basic credentials are form-urlencoded (RFC 6749 §2.3.1)", func(t *testing.T) {
		e := newEnv(t)
		// A secret containing '%' and '+' must round-trip when URL-encoded.
		// Register such a client via RFC 7591 first.
		status, body := registerClient(t, e, map[string]any{
			"client_name": "enc-test", "grant_types": []string{"client_credentials"},
			"token_endpoint_auth_method": "client_secret_basic",
		})
		if status != http.StatusCreated {
			t.Fatalf("register: %d %v", status, body)
		}
		id, secret := str(body, "client_id"), str(body, "client_secret")
		st, out := e.tokenRequest(id, secret, url.Values{"grant_type": {"client_credentials"}})
		if st != http.StatusOK {
			t.Fatalf("url-encoded basic auth failed: %d %v", st, out)
		}
	})
	t.Run("cache headers are no-store", func(t *testing.T) {
		e := newEnv(t)
		req, _ := http.NewRequest("POST", e.idp.URL+"/realms/test/token", strings.NewReader(grant.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("service", url.QueryEscape(webAppSecret))
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
			t.Errorf("Cache-Control %q, want no-store", cc)
		}
	})
}

func TestAuthorizationCodeGrant(t *testing.T) {
	t.Run("happy path issues all three tokens", func(t *testing.T) {
		e := newEnv(t)
		body := e.exchangeCode(e.obtainCode(nil))
		if str(body, "token_type") != "Bearer" {
			t.Errorf("token_type %q", str(body, "token_type"))
		}
		if body["expires_in"].(float64) != 600 {
			t.Errorf("expires_in %v, want 600", body["expires_in"])
		}
		if str(body, "access_token") == "" || str(body, "id_token") == "" || str(body, "refresh_token") == "" {
			t.Fatalf("missing tokens: %v", body)
		}
		if !strings.Contains(str(body, "scope"), "openid") {
			t.Errorf("scope: %q", str(body, "scope"))
		}
	})
	t.Run("no offline_access means no refresh token", func(t *testing.T) {
		e := newEnv(t)
		code := e.obtainCode(map[string]string{"scope": "openid profile"})
		status, body := e.tokenRequest("web-app", webAppSecret, url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {"https://app.example/callback"},
		})
		if status != http.StatusOK {
			t.Fatalf("%d: %v", status, body)
		}
		if str(body, "refresh_token") != "" {
			t.Error("refresh token issued without offline_access")
		}
	})
	t.Run("code bound to client", func(t *testing.T) {
		e := newEnv(t)
		code := e.obtainCode(nil)
		// portal (different confidential client) tries to redeem web-app's code.
		status, body := e.tokenRequest("portal", webAppSecret, url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {"https://app.example/callback"},
		})
		if status != http.StatusBadRequest || str(body, "error") != "invalid_grant" {
			t.Fatalf("%d: %v", status, body)
		}
	})
	t.Run("redirect_uri must match issuance", func(t *testing.T) {
		e := newEnv(t)
		code := e.obtainCode(nil)
		status, body := e.tokenRequest("web-app", webAppSecret, url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {"https://app.example/other"},
		})
		if status != http.StatusBadRequest || str(body, "error") != "invalid_grant" {
			t.Fatalf("%d: %v", status, body)
		}
	})
	t.Run("expired code rejected", func(t *testing.T) {
		e := newEnv(t)
		code := e.obtainCode(nil)
		e.clock.Advance(2 * time.Minute) // > 60s TTL
		status, body := e.tokenRequest("web-app", webAppSecret, url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {"https://app.example/callback"},
		})
		if status != http.StatusBadRequest || str(body, "error") != "invalid_grant" {
			t.Fatalf("%d: %v", status, body)
		}
	})
	t.Run("code replay revokes issued refresh family", func(t *testing.T) {
		e := newEnv(t)
		code := e.obtainCode(nil)
		first := e.exchangeCode(code)
		rt := str(first, "refresh_token")

		// Replay the code: must fail…
		status, body := e.tokenRequest("web-app", webAppSecret, url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {"https://app.example/callback"},
		})
		if status != http.StatusBadRequest || str(body, "error") != "invalid_grant" {
			t.Fatalf("replay: %d %v", status, body)
		}
		// …and the refresh token from the first redemption must now be dead.
		status, body = e.tokenRequest("web-app", webAppSecret, url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {rt},
		})
		if status != http.StatusBadRequest || str(body, "error") != "invalid_grant" {
			t.Fatalf("refresh after code replay should be revoked: %d %v", status, body)
		}
	})
	t.Run("unknown grant_type", func(t *testing.T) {
		e := newEnv(t)
		status, body := e.tokenRequest("web-app", webAppSecret, url.Values{
			"grant_type": {"password"}, "username": {"alice"}, "password": {testUserPassword},
		})
		// ROPC is deliberately unsupported; client isn't authorized for it.
		if status != http.StatusBadRequest {
			t.Fatalf("%d: %v", status, body)
		}
		got := str(body, "error")
		if got != "unauthorized_client" && got != "unsupported_grant_type" {
			t.Errorf("error %q", got)
		}
	})
}

func TestPKCE(t *testing.T) {
	obtainSPACode := func(e *env, challenge string) string {
		return e.obtainCode(map[string]string{
			"client_id":             "spa",
			"redirect_uri":          "https://spa.example/callback",
			"code_challenge":        challenge,
			"code_challenge_method": "S256",
		})
	}
	spaExchange := func(e *env, code, verifier string) (int, map[string]any) {
		form := url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri": {"https://spa.example/callback"},
			"client_id":    {"spa"},
		}
		if verifier != "" {
			form.Set("code_verifier", verifier)
		}
		return e.tokenRequest("", "", form)
	}

	t.Run("happy path", func(t *testing.T) {
		e := newEnv(t)
		verifier, challenge := pkcePair()
		status, body := spaExchange(e, obtainSPACode(e, challenge), verifier)
		if status != http.StatusOK || str(body, "access_token") == "" {
			t.Fatalf("%d: %v", status, body)
		}
	})
	t.Run("wrong verifier rejected", func(t *testing.T) {
		e := newEnv(t)
		_, challenge := pkcePair()
		status, body := spaExchange(e, obtainSPACode(e, challenge), strings.Repeat("wrong-vfy", 6)[:43])
		if status != http.StatusBadRequest || str(body, "error") != "invalid_grant" {
			t.Fatalf("%d: %v", status, body)
		}
	})
	t.Run("missing verifier rejected", func(t *testing.T) {
		e := newEnv(t)
		_, challenge := pkcePair()
		status, body := spaExchange(e, obtainSPACode(e, challenge), "")
		if status != http.StatusBadRequest || str(body, "error") != "invalid_grant" {
			t.Fatalf("%d: %v", status, body)
		}
	})
	t.Run("RFC 7636 appendix B test vector", func(t *testing.T) {
		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		wantChallenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
		sum := pkceS256(verifier)
		if sum != wantChallenge {
			t.Fatalf("S256(%s) = %s, want %s", verifier, sum, wantChallenge)
		}
	})
	t.Run("public client with secret rejected", func(t *testing.T) {
		e := newEnv(t)
		verifier, challenge := pkcePair()
		code := obtainSPACode(e, challenge)
		status, body := e.tokenRequest("spa", "some-secret", url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"redirect_uri":  {"https://spa.example/callback"},
			"code_verifier": {verifier},
		})
		if status != http.StatusUnauthorized || str(body, "error") != "invalid_client" {
			t.Fatalf("%d: %v", status, body)
		}
	})
}

func pkceS256(verifier string) string {
	sum := sha256Of(verifier)
	return base64.RawURLEncoding.EncodeToString(sum)
}

func TestRefreshTokenRotation(t *testing.T) {
	refresh := func(e *env, rt string, extra url.Values) (int, map[string]any) {
		form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {rt}}
		for k, vs := range extra {
			form[k] = vs
		}
		return e.tokenRequest("web-app", webAppSecret, form)
	}

	t.Run("rotation issues a new token and kills the old", func(t *testing.T) {
		e := newEnv(t)
		rt0 := str(e.exchangeCode(e.obtainCode(nil)), "refresh_token")
		status, body := refresh(e, rt0, nil)
		if status != http.StatusOK {
			t.Fatalf("%d: %v", status, body)
		}
		rt1 := str(body, "refresh_token")
		if rt1 == "" || rt1 == rt0 {
			t.Fatalf("no rotation: %q", rt1)
		}
		// ID token on refresh has no nonce (OIDC §12.2) — decode and check.
		if idt := str(body, "id_token"); idt != "" {
			if payload := jwtPayload(t, idt); strings.Contains(payload, "n0nce") {
				t.Error("refreshed ID token carries the original nonce")
			}
		}
		// New generation works.
		if status, body = refresh(e, rt1, nil); status != http.StatusOK {
			t.Fatalf("second refresh: %d %v", status, body)
		}
	})
	t.Run("reuse of rotated token revokes the whole family", func(t *testing.T) {
		e := newEnv(t)
		rt0 := str(e.exchangeCode(e.obtainCode(nil)), "refresh_token")
		status, body := refresh(e, rt0, nil)
		if status != http.StatusOK {
			t.Fatal(status)
		}
		rt1 := str(body, "refresh_token")

		// Attacker replays rt0.
		if status, body = refresh(e, rt0, nil); status != http.StatusBadRequest || str(body, "error") != "invalid_grant" {
			t.Fatalf("replay: %d %v", status, body)
		}
		// Legitimate rt1 is now dead too — family revoked.
		if status, body = refresh(e, rt1, nil); status != http.StatusBadRequest || str(body, "error") != "invalid_grant" {
			t.Fatalf("family not revoked: %d %v", status, body)
		}
	})
	t.Run("wrong client presenting the token kills the family", func(t *testing.T) {
		e := newEnv(t)
		rt0 := str(e.exchangeCode(e.obtainCode(nil)), "refresh_token")
		status, body := e.tokenRequest("portal", webAppSecret, url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {rt0},
		})
		if status != http.StatusBadRequest || str(body, "error") != "invalid_grant" {
			t.Fatalf("%d: %v", status, body)
		}
		if status, body = refresh(e, rt0, nil); status != http.StatusBadRequest {
			t.Fatalf("family survived cross-client presentation: %d %v", status, body)
		}
	})
	t.Run("scope narrowing allowed, expansion rejected", func(t *testing.T) {
		e := newEnv(t)
		rt0 := str(e.exchangeCode(e.obtainCode(nil)), "refresh_token")
		status, body := refresh(e, rt0, url.Values{"scope": {"openid profile"}})
		if status != http.StatusOK || str(body, "scope") != "openid profile" {
			t.Fatalf("narrowing failed: %d %v", status, body)
		}
		rt1 := str(body, "refresh_token")
		status, body = refresh(e, rt1, url.Values{"scope": {"openid profile email offline_access admin"}})
		if status != http.StatusBadRequest || str(body, "error") != "invalid_scope" {
			t.Fatalf("expansion allowed: %d %v", status, body)
		}
	})
	t.Run("absolute expiry is inherited across rotations", func(t *testing.T) {
		e := newEnv(t)
		rt := str(e.exchangeCode(e.obtainCode(nil)), "refresh_token")
		// Rotate a few times while advancing close to the 30d limit.
		for range 3 {
			e.clock.Advance(9 * 24 * time.Hour)
			status, body := refresh(e, rt, nil)
			if status != http.StatusOK {
				t.Fatalf("%d: %v", status, body)
			}
			rt = str(body, "refresh_token")
		}
		// 27 days in; 4 more crosses the absolute boundary.
		e.clock.Advance(4 * 24 * time.Hour)
		status, body := refresh(e, rt, nil)
		if status != http.StatusBadRequest || str(body, "error") != "invalid_grant" {
			t.Fatalf("rotation extended absolute lifetime: %d %v", status, body)
		}
	})
}

func TestClientCredentialsGrant(t *testing.T) {
	t.Run("openid scope rejected", func(t *testing.T) {
		e := newEnv(t)
		status, body := e.tokenRequest("service", webAppSecret, url.Values{
			"grant_type": {"client_credentials"}, "scope": {"openid"},
		})
		if status != http.StatusBadRequest || str(body, "error") != "invalid_scope" {
			t.Fatalf("%d: %v", status, body)
		}
	})
	t.Run("subject is service-prefixed", func(t *testing.T) {
		e := newEnv(t)
		_, body := e.tokenRequest("service", webAppSecret, url.Values{
			"grant_type": {"client_credentials"}, "scope": {"inventory:read"},
		})
		payload := jwtPayload(t, str(body, "access_token"))
		if !strings.Contains(payload, `"sub":"service:service"`) {
			t.Errorf("service subject not namespaced: %s", payload)
		}
	})
}
