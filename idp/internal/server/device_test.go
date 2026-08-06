package server_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// startDeviceFlow requests a device code for the public "cli" client.
func startDeviceFlow(t *testing.T, e *env) map[string]any {
	t.Helper()
	status, body := e.tokenRequestPath(t, "/realms/test/device/code", "", "", url.Values{
		"client_id": {"cli"},
		"scope":     {"openid profile offline_access"},
	})
	if status != http.StatusOK {
		t.Fatalf("device code request: %d %v", status, body)
	}
	for _, f := range []string{"device_code", "user_code", "verification_uri", "verification_uri_complete"} {
		if str(body, f) == "" {
			t.Fatalf("missing %s: %v", f, body)
		}
	}
	if body["interval"].(float64) != 5 {
		t.Errorf("interval %v", body["interval"])
	}
	return body
}

// tokenRequestPath generalizes tokenRequest to any endpoint path.
func (e *env) tokenRequestPath(t *testing.T, path, clientID, secret string, form url.Values) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest("POST", e.idp.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if clientID != "" {
		req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(secret))
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out := map[string]any{}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out)
	return resp.StatusCode, out
}

func (e *env) pollDevice(t *testing.T, deviceCode string) (int, map[string]any) {
	t.Helper()
	return e.tokenRequestPath(t, "/realms/test/token", "", "", url.Values{
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
		"device_code": {deviceCode},
		"client_id":   {"cli"},
	})
}

// approveDevice drives the browser side: login (if needed) + code entry.
func approveDevice(t *testing.T, e *env, userCode, decision string) {
	t.Helper()
	resp, body := e.get("/realms/test/device")
	if strings.Contains(body, "Sign in") {
		resp, body = e.login(body, "alice", testUserPassword)
		if resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("device login: %d", resp.StatusCode)
		}
		resp, body = e.get(resp.Header.Get("Location"))
	}
	if !strings.Contains(body, "Enter the code") {
		t.Fatalf("no device form: %s", firstLine(body))
	}
	csrf := csrfRe.FindStringSubmatch(body)
	resp, body = e.postForm("/realms/test/device", url.Values{
		"csrf_token": {csrf[1]},
		"user_code":  {userCode},
		"decision":   {decision},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device submit: %d %s", resp.StatusCode, firstLine(body))
	}
	if decision != "allow" {
		return
	}
	// Approval is two-step: the code POST answers with the consent page
	// naming the client and its scopes, and only the confirmed POST grants.
	if !strings.Contains(body, "Authorize") {
		t.Fatalf("no device consent page: %s", firstLine(body))
	}
	csrf = csrfRe.FindStringSubmatch(body)
	resp, body = e.postForm("/realms/test/device", url.Values{
		"csrf_token": {csrf[1]},
		"user_code":  {userCode},
		"decision":   {"allow"},
		"confirmed":  {"1"},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("device confirm: %d %s", resp.StatusCode, firstLine(body))
	}
}

func TestDeviceFlow(t *testing.T) {
	t.Run("full happy path", func(t *testing.T) {
		e := newEnv(t)
		grant := startDeviceFlow(t, e)
		dc := str(grant, "device_code")

		// Pending before approval.
		status, body := e.pollDevice(t, dc)
		if status != http.StatusBadRequest || str(body, "error") != "authorization_pending" {
			t.Fatalf("pre-approval poll: %d %v", status, body)
		}
		// Polling faster than interval → slow_down.
		e.clock.Advance(2 * time.Second)
		if _, body = e.pollDevice(t, dc); str(body, "error") != "slow_down" {
			t.Fatalf("fast poll: %v", body)
		}

		approveDevice(t, e, str(grant, "user_code"), "allow")

		e.clock.Advance(6 * time.Second)
		status, body = e.pollDevice(t, dc)
		if status != http.StatusOK || str(body, "access_token") == "" {
			t.Fatalf("post-approval poll: %d %v", status, body)
		}
		if str(body, "refresh_token") == "" || str(body, "id_token") == "" {
			t.Errorf("tokens missing: %v", body)
		}
		// Device code is spent.
		e.clock.Advance(6 * time.Second)
		if status, body = e.pollDevice(t, dc); status != http.StatusBadRequest || str(body, "error") != "invalid_grant" {
			t.Fatalf("spent device code: %d %v", status, body)
		}
	})

	t.Run("approval names the client and its scopes, and records consent", func(t *testing.T) {
		// RFC 8628 §3.3: the user typed a code with no idea what it belongs
		// to. Approving without seeing the application and the permissions is
		// a grant /authorize would never have issued unasked.
		e := newEnv(t)
		grant := startDeviceFlow(t, e)

		resp, body := e.get("/realms/test/device")
		if strings.Contains(body, "Sign in") {
			resp, _ = e.login(body, "alice", testUserPassword)
			_, body = e.get(resp.Header.Get("Location"))
		}
		_, body = e.postForm("/realms/test/device", url.Values{
			"csrf_token": {csrfRe.FindStringSubmatch(body)[1]},
			"user_code":  {str(grant, "user_code")},
			"decision":   {"allow"},
		})
		if !strings.Contains(body, "Test CLI") {
			t.Errorf("approval page does not name the client:\n%s", body)
		}
		if !strings.Contains(body, "refresh tokens") {
			t.Errorf("approval page does not list the offline_access scope:\n%s", body)
		}

		// Confirming records a reviewable/revocable consent, as /authorize does.
		e.postForm("/realms/test/device", url.Values{
			"csrf_token": {csrfRe.FindStringSubmatch(body)[1]},
			"user_code":  {str(grant, "user_code")},
			"decision":   {"allow"},
			"confirmed":  {"1"},
		})
		if _, err := e.store.Consents().Get(t.Context(), "test", "usr_1", "cli"); err != nil {
			t.Errorf("device approval left no consent record: %v", err)
		}
	})

	t.Run("user code is confusion-normalized", func(t *testing.T) {
		e := newEnv(t)
		grant := startDeviceFlow(t, e)
		mangled := strings.ToLower(strings.ReplaceAll(str(grant, "user_code"), "-", " "))
		approveDevice(t, e, mangled, "allow")
		e.clock.Advance(6 * time.Second)
		status, body := e.pollDevice(t, str(grant, "device_code"))
		if status != http.StatusOK {
			t.Fatalf("normalized code not accepted: %d %v", status, body)
		}
	})

	t.Run("denial", func(t *testing.T) {
		e := newEnv(t)
		grant := startDeviceFlow(t, e)
		approveDevice(t, e, str(grant, "user_code"), "deny")
		e.clock.Advance(6 * time.Second)
		status, body := e.pollDevice(t, str(grant, "device_code"))
		if status != http.StatusBadRequest || str(body, "error") != "access_denied" {
			t.Fatalf("%d %v", status, body)
		}
	})

	t.Run("expiry at the token endpoint", func(t *testing.T) {
		e := newEnv(t)
		grant := startDeviceFlow(t, e)
		e.clock.Advance(11 * time.Minute)
		status, body := e.pollDevice(t, str(grant, "device_code"))
		if status != http.StatusBadRequest || str(body, "error") != "expired_token" {
			t.Fatalf("%d %v", status, body)
		}
	})

	t.Run("expired code rejected in the browser UI", func(t *testing.T) {
		// A fresh grant, expired but never polled (polling would delete it),
		// must be refused at the approval page too.
		e := newEnv(t)
		grant := startDeviceFlow(t, e)
		e.clock.Advance(11 * time.Minute)
		resp, pageBody := e.get("/realms/test/device")
		if strings.Contains(pageBody, "Sign in") {
			resp, pageBody = e.login(pageBody, "alice", testUserPassword)
			_, pageBody = e.get(resp.Header.Get("Location"))
		}
		csrf := csrfRe.FindStringSubmatch(pageBody)
		_, out := e.postForm("/realms/test/device", url.Values{
			"csrf_token": {csrf[1]},
			"user_code":  {str(grant, "user_code")},
			"decision":   {"allow"},
		})
		if !strings.Contains(out, "expired") {
			t.Errorf("expired code approved in UI: %s", firstLine(out))
		}
	})

	t.Run("wrong client cannot redeem", func(t *testing.T) {
		e := newEnv(t)
		grant := startDeviceFlow(t, e)
		approveDevice(t, e, str(grant, "user_code"), "allow")
		e.clock.Advance(6 * time.Second)
		status, body := e.tokenRequestPath(t, "/realms/test/token", "web-app", webAppSecret, url.Values{
			"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
			"device_code": {str(grant, "device_code")},
		})
		if status != http.StatusBadRequest {
			t.Fatalf("%d %v", status, body)
		}
		got := str(body, "error")
		if got != "invalid_grant" && got != "unauthorized_client" {
			t.Errorf("error %q", got)
		}
	})
}
