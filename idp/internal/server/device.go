package server

import (
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/aikazzh/portfolio/idp/internal/oauth"
	"github.com/aikazzh/portfolio/idp/internal/secrets"
	"github.com/aikazzh/portfolio/idp/internal/storage"
)

// Device flow (RFC 8628) constants.
const (
	deviceCodeTTL      = 10 * time.Minute
	devicePollInterval = 5 // seconds
)

// handleDeviceCode implements the device authorization endpoint (§3.1–3.2).
func (s *Server) handleDeviceCode(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	realm, ok := s.realm(w, r)
	if !ok {
		return
	}
	if err := r.ParseForm(); err != nil {
		oauth.WriteTokenError(w, oauth.E(oauth.ErrInvalidRequest, "malformed form body"), false)
		return
	}
	client, basicAttempted, authErr := s.authenticateClient(r, realm.Name)
	if authErr != nil {
		oauth.WriteTokenError(w, authErr, basicAttempted)
		return
	}
	if !client.AllowsGrant("urn:ietf:params:oauth:grant-type:device_code") {
		oauth.WriteTokenError(w, oauth.E(oauth.ErrUnauthorizedClient, "client may not use the device flow"), false)
		return
	}
	scopes := oauth.ParseScopes(r.PostFormValue("scope"))
	if invalid := scopes.Subtract(client.Scopes); len(invalid) > 0 {
		oauth.WriteTokenError(w, oauth.E(oauth.ErrInvalidScope, "scope not allowed: %s", invalid.String()), false)
		return
	}

	deviceCode := secrets.New("dc_")
	display, normalized := secrets.NewUserCode()
	now := s.now()
	dc := storage.DeviceCode{
		DeviceCodeHash: secrets.Hash(deviceCode),
		UserCode:       normalized,
		RealmName:      realm.Name,
		ClientID:       client.ClientID,
		Scopes:         scopes,
		Status:         storage.DeviceStatusPending,
		Interval:       devicePollInterval,
		ExpiresAt:      now.Add(deviceCodeTTL),
		CreatedAt:      now,
	}
	if err := s.cfg.Store.DeviceCodes().Create(r.Context(), dc); err != nil {
		oauth.WriteTokenError(w, oauth.E(oauth.ErrServerError, ""), false)
		return
	}
	verificationURI := s.cfg.BaseURL + "/realms/" + realm.Name + "/device"
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 display,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURI + "?user_code=" + url.QueryEscape(display),
		"expires_in":                int(deviceCodeTTL.Seconds()),
		"interval":                  devicePollInterval,
	})
}

// handleDevicePage renders the user-code entry form (§3.3). Requires a login
// session; anonymous visitors see the login form first.
func (s *Server) handleDevicePage(w http.ResponseWriter, r *http.Request) {
	realm, ok := s.realm(w, r)
	if !ok {
		return
	}
	_, _, err := s.currentSession(r, realm)
	if err != nil {
		s.renderDeviceLogin(w, r, realm)
		return
	}
	csrf := s.ensureCSRF(w, r, realm.Name)
	renderTemplate(w, deviceTemplate, map[string]any{
		"Title":    "Device sign-in",
		"Action":   "/realms/" + realm.Name + "/device",
		"UserCode": r.URL.Query().Get("user_code"),
		"CSRF":     csrf,
	})
}

// renderDeviceLogin shows the login form with the device page as return
// target. The device page is not /authorize, so it gets its own return
// validation: we reuse the login handler by pointing return_to at a synthetic
// authorize URL is NOT acceptable — instead the device page performs its own
// login redirect using the standard login form with a device return path.
func (s *Server) renderDeviceLogin(w http.ResponseWriter, r *http.Request, realm storage.Realm) {
	csrf := s.ensureCSRF(w, r, realm.Name)
	renderTemplate(w, loginTemplate, map[string]any{
		"Title":      "Sign in",
		"ClientName": "device sign-in",
		"Action":     "/realms/" + realm.Name + "/login",
		"ReturnTo":   "/realms/" + realm.Name + "/device?" + r.URL.RawQuery,
		"CSRF":       csrf,
	})
}

// handleDeviceSubmit processes approval/denial of a user code.
func (s *Server) handleDeviceSubmit(w http.ResponseWriter, r *http.Request) {
	realm, ok := s.realm(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		s.writePageError(w, http.StatusBadRequest, "Invalid request", "Malformed form submission.")
		return
	}
	_, user, err := s.currentSession(r, realm)
	if err != nil {
		s.renderDeviceLogin(w, r, realm)
		return
	}
	if !s.checkCSRF(r, realm.Name) {
		s.writePageError(w, http.StatusForbidden, "Session expired", "Please try again.")
		return
	}
	renderErr := func(msg string) {
		csrf := s.ensureCSRF(w, r, realm.Name)
		renderTemplate(w, deviceTemplate, map[string]any{
			"Title":  "Device sign-in",
			"Action": "/realms/" + realm.Name + "/device",
			"CSRF":   csrf,
			"Error":  msg,
		})
	}
	dc, err := s.cfg.Store.DeviceCodes().GetByUserCode(ctx, realm.Name,
		secrets.NormalizeUserCode(r.PostFormValue("user_code")))
	if err != nil {
		renderErr("Unknown code. Check the code shown on your device.")
		return
	}
	if s.now().After(dc.ExpiresAt) {
		renderErr("That code has expired. Start again on your device.")
		return
	}
	status := storage.DeviceStatusDenied
	if r.PostFormValue("decision") == "allow" {
		status = storage.DeviceStatusApproved
	}
	if err := s.cfg.Store.DeviceCodes().SetStatus(ctx, realm.Name, dc.DeviceCodeHash, status, user.ID); err != nil {
		renderErr("That code was already used.")
		return
	}
	if status == storage.DeviceStatusApproved {
		s.writePageError(w, http.StatusOK, "Device approved",
			"You can return to your device — it will finish signing in shortly.")
	} else {
		s.writePageError(w, http.StatusOK, "Device denied", "The device sign-in was denied.")
	}
}

// grantDeviceCode implements the token-endpoint side of the flow (§3.4–3.5).
func (s *Server) grantDeviceCode(r *http.Request, realm storage.Realm, client storage.Client) (*tokenResponse, *oauth.Error) {
	ctx := r.Context()
	presented := r.PostFormValue("device_code")
	if presented == "" {
		return nil, oauth.E(oauth.ErrInvalidRequest, "device_code is required")
	}
	hash := secrets.Hash(presented)
	dc, err := s.cfg.Store.DeviceCodes().GetByDeviceCode(ctx, realm.Name, hash)
	if err != nil {
		return nil, oauth.E(oauth.ErrInvalidGrant, "unknown device_code")
	}
	if dc.ClientID != client.ClientID {
		return nil, oauth.E(oauth.ErrInvalidGrant, "device_code was not issued to this client")
	}
	now := s.now()
	if now.After(dc.ExpiresAt) {
		_ = s.cfg.Store.DeviceCodes().Delete(ctx, realm.Name, hash)
		return nil, oauth.E(oauth.ErrExpiredToken, "device_code expired")
	}
	// Poll pacing (§3.5): faster than interval ⇒ slow_down.
	prev, err := s.cfg.Store.DeviceCodes().TouchPoll(ctx, realm.Name, hash, now)
	if err != nil {
		return nil, oauth.E(oauth.ErrServerError, "")
	}
	if !prev.IsZero() && now.Sub(prev) < time.Duration(dc.Interval)*time.Second {
		return nil, oauth.E(oauth.ErrSlowDown, "")
	}

	switch dc.Status {
	case storage.DeviceStatusPending:
		return nil, oauth.E(oauth.ErrAuthorizationPending, "")
	case storage.DeviceStatusDenied:
		_ = s.cfg.Store.DeviceCodes().Delete(ctx, realm.Name, hash)
		return nil, oauth.E(oauth.ErrAccessDenied, "user denied the request")
	case storage.DeviceStatusApproved:
	default:
		return nil, oauth.E(oauth.ErrServerError, "")
	}

	user, err := s.cfg.Store.Users().Get(ctx, realm.Name, dc.UserID)
	if err != nil || user.Disabled {
		return nil, oauth.E(oauth.ErrInvalidGrant, "user unavailable")
	}
	resp, oerr := s.issueUserTokens(ctx, realm, client, user, dc.Scopes, now, "", "")
	if oerr != nil {
		return nil, oerr
	}
	if err := s.cfg.Store.DeviceCodes().Delete(ctx, realm.Name, hash); err != nil && !errors.Is(err, storage.ErrNotFound) {
		s.cfg.Logger.Warn("device code cleanup failed", "err", err)
	}
	return resp, nil
}
