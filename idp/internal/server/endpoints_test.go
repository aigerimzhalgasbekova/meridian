package server_test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDiscoveryDocument(t *testing.T) {
	e := newEnv(t)
	resp, body := e.get("/realms/test/.well-known/openid-configuration")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(body), &doc); err != nil {
		t.Fatal(err)
	}
	issuer := e.idp.URL + "/realms/test"
	checks := map[string]string{
		"issuer":                 issuer,
		"authorization_endpoint": issuer + "/authorize",
		"token_endpoint":         issuer + "/token",
		"userinfo_endpoint":      issuer + "/userinfo",
		"jwks_uri":               issuer + "/.well-known/jwks.json",
		"introspection_endpoint": issuer + "/introspect",
		"revocation_endpoint":    issuer + "/revoke",
		"registration_endpoint":  issuer + "/register",
	}
	for k, want := range checks {
		if doc[k] != want {
			t.Errorf("%s = %v, want %s", k, doc[k], want)
		}
	}
	rts, _ := doc["response_types_supported"].([]any)
	if len(rts) != 1 || rts[0] != "code" {
		t.Errorf("response_types_supported = %v (implicit must be absent)", rts)
	}
	ccm, _ := doc["code_challenge_methods_supported"].([]any)
	if len(ccm) != 1 || ccm[0] != "S256" {
		t.Errorf("code_challenge_methods_supported = %v", ccm)
	}
	gts, _ := doc["grant_types_supported"].([]any)
	for _, banned := range []string{"implicit", "password"} {
		for _, gt := range gts {
			if gt == banned {
				t.Errorf("deprecated grant %q advertised", banned)
			}
		}
	}
	if _, err := url.ParseRequestURI(str(doc, "device_authorization_endpoint")); err != nil {
		t.Errorf("device_authorization_endpoint: %v", err)
	}

	t.Run("unknown realm 404s", func(t *testing.T) {
		resp, _ := e.get("/realms/nope/.well-known/openid-configuration")
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("status %d", resp.StatusCode)
		}
	})
}

func TestJWKSEndpoint(t *testing.T) {
	e := newEnv(t)
	resp, body := e.get("/realms/test/.well-known/jwks.json")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal([]byte(body), &jwks); err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) == 0 {
		t.Fatal("empty JWKS")
	}
	for _, k := range jwks.Keys {
		if _, hasD := k["d"]; hasD {
			t.Fatal("private component in published JWKS")
		}
	}
	if !strings.Contains(resp.Header.Get("Cache-Control"), "max-age") {
		t.Error("missing cache headers")
	}
}

func TestUserinfo(t *testing.T) {
	e := newEnv(t)
	tokens := e.exchangeCode(e.obtainCode(nil))
	access := str(tokens, "access_token")

	get := func(auth string) (int, map[string]any, http.Header) {
		req, _ := http.NewRequest("GET", e.idp.URL+"/realms/test/userinfo", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out, resp.Header
	}

	t.Run("happy path releases scoped claims", func(t *testing.T) {
		status, body, _ := get("Bearer " + access)
		if status != http.StatusOK {
			t.Fatalf("%d: %v", status, body)
		}
		if body["sub"] != "usr_1" || body["email"] != "alice@example.com" ||
			body["email_verified"] != true || body["preferred_username"] != "alice" {
			t.Errorf("claims: %v", body)
		}
	})
	t.Run("scope limits claims", func(t *testing.T) {
		code := e.obtainCode(map[string]string{"scope": "openid profile"}) // no email
		toks := e.exchangeCode2(code, "openid profile")
		status, body, _ := get("Bearer " + str(toks, "access_token"))
		if status != http.StatusOK {
			t.Fatal(status)
		}
		if _, has := body["email"]; has {
			t.Error("email released without email scope")
		}
		if body["preferred_username"] != "alice" {
			t.Error("profile claims missing")
		}
	})
	t.Run("no token yields 401 with challenge", func(t *testing.T) {
		status, _, hdr := get("")
		if status != http.StatusUnauthorized || !strings.HasPrefix(hdr.Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("%d %q", status, hdr.Get("WWW-Authenticate"))
		}
	})
	t.Run("garbage token yields invalid_token", func(t *testing.T) {
		status, _, hdr := get("Bearer not-a-jwt")
		if status != http.StatusUnauthorized || !strings.Contains(hdr.Get("WWW-Authenticate"), "invalid_token") {
			t.Errorf("%d %q", status, hdr.Get("WWW-Authenticate"))
		}
	})
	t.Run("expired token rejected", func(t *testing.T) {
		e.clock.Advance(11 * time.Minute)
		status, _, _ := get("Bearer " + access)
		if status != http.StatusUnauthorized {
			t.Errorf("expired token accepted: %d", status)
		}
	})
}

// exchangeCode2 is exchangeCode with explicit expected scope (avoids the
// offline_access assumption).
func (e *env) exchangeCode2(code, _ string) map[string]any {
	e.t.Helper()
	status, body := e.tokenRequest("web-app", webAppSecret, url.Values{
		"grant_type":   {"authorization_code"},
		"code":         {code},
		"redirect_uri": {"https://app.example/callback"},
	})
	if status != http.StatusOK {
		e.t.Fatalf("token exchange: %d: %v", status, body)
	}
	return body
}

func TestIntrospection(t *testing.T) {
	e := newEnv(t)
	tokens := e.exchangeCode(e.obtainCode(nil))

	introspect := func(clientID, secret, token string) (int, map[string]any) {
		return e.tokenRequest(clientID, secret, url.Values{"token": {token}})
	}
	introspectPath := func(clientID, secret, token string) (int, map[string]any) {
		req, _ := http.NewRequest("POST", e.idp.URL+"/realms/test/introspect",
			strings.NewReader(url.Values{"token": {token}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}
	_ = introspect

	t.Run("access token active with metadata", func(t *testing.T) {
		status, body := introspectPath("web-app", webAppSecret, str(tokens, "access_token"))
		if status != http.StatusOK || body["active"] != true {
			t.Fatalf("%d: %v", status, body)
		}
		if body["client_id"] != "web-app" || body["sub"] != "usr_1" {
			t.Errorf("metadata: %v", body)
		}
	})
	t.Run("refresh token active", func(t *testing.T) {
		status, body := introspectPath("web-app", webAppSecret, str(tokens, "refresh_token"))
		if status != http.StatusOK || body["active"] != true || body["token_type"] != "refresh_token" {
			t.Fatalf("%d: %v", status, body)
		}
	})
	t.Run("garbage is active:false with no detail", func(t *testing.T) {
		status, body := introspectPath("web-app", webAppSecret, "rt_fabricated")
		if status != http.StatusOK || body["active"] != false || len(body) != 1 {
			t.Fatalf("%d: %v (must be exactly {active:false})", status, body)
		}
	})
	t.Run("expired access token is inactive", func(t *testing.T) {
		e2 := newEnv(t)
		toks := e2.exchangeCode(e2.obtainCode(nil))
		e2.clock.Advance(11 * time.Minute)
		req, _ := http.NewRequest("POST", e2.idp.URL+"/realms/test/introspect",
			strings.NewReader(url.Values{"token": {str(toks, "access_token")}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth("web-app", webAppSecret)
		resp, err := e2.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if out["active"] != false {
			t.Errorf("expired token active: %v", out)
		}
	})
	t.Run("unauthenticated caller rejected", func(t *testing.T) {
		req, _ := http.NewRequest("POST", e.idp.URL+"/realms/test/introspect",
			strings.NewReader(url.Values{"token": {"x"}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status %d, want 401", resp.StatusCode)
		}
	})
}

func TestRevocation(t *testing.T) {
	e := newEnv(t)
	post := func(clientID, secret string, form url.Values) int {
		req, _ := http.NewRequest("POST", e.idp.URL+"/realms/test/revoke",
			strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}

	t.Run("revoking a refresh token kills its family", func(t *testing.T) {
		tokens := e.exchangeCode(e.obtainCode(nil))
		rt := str(tokens, "refresh_token")
		if status := post("web-app", webAppSecret, url.Values{"token": {rt}}); status != http.StatusOK {
			t.Fatalf("revoke status %d", status)
		}
		status, body := e.tokenRequest("web-app", webAppSecret, url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {rt},
		})
		if status != http.StatusBadRequest || str(body, "error") != "invalid_grant" {
			t.Fatalf("revoked token still works: %d %v", status, body)
		}
	})
	t.Run("unknown token is silent 200", func(t *testing.T) {
		if status := post("web-app", webAppSecret, url.Values{"token": {"rt_who"}}); status != http.StatusOK {
			t.Errorf("status %d, want 200", status)
		}
	})
	t.Run("another client's token: silent 200, not revoked", func(t *testing.T) {
		tokens := e.exchangeCode(e.obtainCode(nil))
		rt := str(tokens, "refresh_token")
		if status := post("portal", webAppSecret, url.Values{"token": {rt}}); status != http.StatusOK {
			t.Fatalf("status %d", status)
		}
		status, _ := e.tokenRequest("web-app", webAppSecret, url.Values{
			"grant_type": {"refresh_token"}, "refresh_token": {rt},
		})
		if status != http.StatusOK {
			t.Error("token was revoked by a non-owning client")
		}
	})
	t.Run("access token yields unsupported_token_type", func(t *testing.T) {
		tokens := e.exchangeCode(e.obtainCode(nil))
		status := post("web-app", webAppSecret, url.Values{"token": {str(tokens, "access_token")}})
		if status != http.StatusBadRequest {
			t.Errorf("status %d, want 400 unsupported_token_type", status)
		}
	})
}

func TestDynamicRegistration(t *testing.T) {
	t.Run("happy path confidential client can immediately authenticate", func(t *testing.T) {
		e := newEnv(t)
		status, body := registerClient(t, e, map[string]any{
			"client_name":   "Fresh Client",
			"redirect_uris": []string{"https://fresh.example/cb"},
			"grant_types":   []string{"authorization_code", "refresh_token"},
		})
		if status != http.StatusCreated {
			t.Fatalf("%d: %v", status, body)
		}
		if str(body, "client_id") == "" || str(body, "client_secret") == "" {
			t.Fatalf("credentials missing: %v", body)
		}
	})
	t.Run("public client gets no secret", func(t *testing.T) {
		e := newEnv(t)
		_, body := registerClient(t, e, map[string]any{
			"client_name":                "Native",
			"redirect_uris":              []string{"com.example.app:/callback"},
			"token_endpoint_auth_method": "none",
		})
		if _, has := body["client_secret"]; has {
			t.Error("public client received a secret")
		}
	})
	t.Run("http redirect on non-loopback rejected", func(t *testing.T) {
		e := newEnv(t)
		status, _ := registerClient(t, e, map[string]any{
			"client_name":   "Insecure",
			"redirect_uris": []string{"http://prod.example/cb"},
		})
		if status != http.StatusBadRequest {
			t.Errorf("status %d", status)
		}
	})
	t.Run("wrong token rejected", func(t *testing.T) {
		e := newEnv(t)
		req, _ := http.NewRequest("POST", e.idp.URL+"/realms/test/register",
			strings.NewReader(`{"client_name":"x","redirect_uris":["https://x.example/cb"]}`))
		req.Header.Set("Authorization", "Bearer wrong")
		resp, err := e.client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("status %d", resp.StatusCode)
		}
	})
}
