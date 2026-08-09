package server

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aikazzh/portfolio/idp/internal/oauth"
	"github.com/aikazzh/portfolio/idp/internal/password"
	"github.com/aikazzh/portfolio/idp/internal/secrets"
	"github.com/aikazzh/portfolio/idp/internal/storage"
)

// handleAuthorize implements the authorization endpoint (RFC 6749 §4.1 +
// OIDC Core §3.1.2). Validation order is dictated by the open-redirect rule:
// nothing may be sent to redirect_uri until both client_id and redirect_uri
// have been validated; failures before that point render an error page.
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	realm, ok := s.realm(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	q := r.URL.Query()

	client, err := s.cfg.Store.Clients().Get(ctx, realm.Name, q.Get("client_id"))
	if err != nil {
		s.writePageError(w, http.StatusBadRequest, "Invalid request",
			"Unknown client. The application that sent you here is misconfigured.")
		return
	}

	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" && len(client.RedirectURIs) == 1 {
		redirectURI = client.RedirectURIs[0]
	}
	if !client.AllowsRedirect(redirectURI) {
		s.writePageError(w, http.StatusBadRequest, "Invalid request",
			"The redirect address is not registered for this application.")
		return
	}
	ru, err := url.Parse(redirectURI)
	if err != nil {
		s.writePageError(w, http.StatusBadRequest, "Invalid request", "Malformed redirect address.")
		return
	}

	// From here on, errors go back to the client per §4.1.2.1.
	state := q.Get("state")
	fail := func(oe *oauth.Error) { oauth.RedirectError(w, r, ru, oe, state) }

	if q.Get("response_type") != "code" {
		fail(oauth.E(oauth.ErrUnsupportedResponseType, "only response_type=code is supported"))
		return
	}
	if !client.AllowsGrant("authorization_code") {
		fail(oauth.E(oauth.ErrUnauthorizedClient, "client may not use the authorization code grant"))
		return
	}

	scopes := oauth.ParseScopes(q.Get("scope"))
	if invalid := scopes.Subtract(client.Scopes); len(invalid) > 0 {
		fail(oauth.E(oauth.ErrInvalidScope, "scope not allowed for this client: %s", invalid.String()))
		return
	}

	challenge := q.Get("code_challenge")
	method := q.Get("code_challenge_method")
	switch {
	case challenge == "" && client.Public:
		// RFC 9700: PKCE is mandatory for public clients.
		fail(oauth.E(oauth.ErrInvalidRequest, "PKCE is required for public clients"))
		return
	case challenge != "" && method != "S256":
		fail(oauth.E(oauth.ErrInvalidRequest, "only code_challenge_method=S256 is supported"))
		return
	case challenge != "" && !oauth.ValidCodeChallenge(challenge):
		fail(oauth.E(oauth.ErrInvalidRequest, "malformed code_challenge"))
		return
	}

	prompt := q.Get("prompt")
	sess, user, sessErr := s.currentSession(r, realm)
	needLogin := sessErr != nil || prompt == "login"
	if !needLogin && q.Get("max_age") != "" {
		maxAge, err := strconv.ParseInt(q.Get("max_age"), 10, 64)
		if err != nil || maxAge < 0 {
			fail(oauth.E(oauth.ErrInvalidRequest, "malformed max_age"))
			return
		}
		if s.now().Sub(sess.AuthenticatedAt) > time.Duration(maxAge)*time.Second {
			needLogin = true
		}
	}
	if needLogin {
		if prompt == "none" {
			fail(oauth.E(oauth.ErrLoginRequired, ""))
			return
		}
		s.renderLogin(w, r, realm, client, r.URL, "")
		return
	}

	if s.needsConsent(r, realm, client, user, scopes, prompt) {
		if prompt == "none" {
			fail(oauth.E(oauth.ErrInteractionRequired, ""))
			return
		}
		s.renderConsent(w, r, realm, client, user, scopes, r.URL)
		return
	}

	// All checks passed: mint the single-use code.
	code := secrets.New("ac_")
	authCode := storage.AuthCode{
		CodeHash:      secrets.Hash(code),
		RealmName:     realm.Name,
		ClientID:      client.ClientID,
		UserID:        user.ID,
		RedirectURI:   redirectURI,
		Scopes:        scopes,
		Nonce:         q.Get("nonce"),
		CodeChallenge: challenge,
		AuthTime:      sess.AuthenticatedAt,
		SessionID:     sess.IDHash,
		ExpiresAt:     s.now().Add(AuthCodeTTL),
		CreatedAt:     s.now(),
	}
	if err := s.cfg.Store.AuthCodes().Create(ctx, authCode); err != nil {
		fail(oauth.E(oauth.ErrServerError, ""))
		return
	}
	dest := *ru
	dq := dest.Query()
	dq.Set("code", code)
	if state != "" {
		dq.Set("state", state)
	}
	dest.RawQuery = dq.Encode()
	// Referrer-Policy: no-referrer is set globally so the code cannot leak
	// through the Referer header of the target page.
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

func (s *Server) needsConsent(r *http.Request, realm storage.Realm, client storage.Client, user storage.User, scopes oauth.Scopes, prompt string) bool {
	if prompt == "consent" {
		return true
	}
	if client.FirstParty {
		return false
	}
	consent, err := s.cfg.Store.Consents().Get(r.Context(), realm.Name, user.ID, client.ClientID)
	if err != nil {
		return true
	}
	return len(scopes.Subtract(consent.Scopes)) > 0
}

// validReturnTo accepts only same-realm authorize or device URLs, preventing
// the login form from becoming an open redirector. These are the two pages
// that require a login session before they can proceed.
func validReturnTo(realm, returnTo string) (*url.URL, bool) {
	u, err := url.Parse(returnTo)
	if err != nil || u.IsAbs() || u.Host != "" {
		return nil, false
	}
	switch u.Path {
	case "/realms/" + realm + "/authorize", "/realms/" + realm + "/device":
		return u, true
	}
	return nil, false
}

// stripPrompt removes a satisfied prompt directive so the post-action
// redirect back to /authorize doesn't loop.
func stripPrompt(u *url.URL, value string) string {
	q := u.Query()
	if q.Get("prompt") == value {
		q.Del("prompt")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (s *Server) renderLogin(w http.ResponseWriter, r *http.Request, realm storage.Realm, client storage.Client, returnTo *url.URL, errMsg string) {
	csrf := s.ensureCSRF(w, r, realm.Name)
	renderTemplate(w, loginTemplate, map[string]any{
		"Title":      "Sign in",
		"ClientName": client.Name,
		"Action":     "/realms/" + realm.Name + "/login",
		"ReturnTo":   returnTo.String(),
		"CSRF":       csrf,
		"Error":      errMsg,
	})
}

func (s *Server) renderConsent(w http.ResponseWriter, r *http.Request, realm storage.Realm, client storage.Client, user storage.User, scopes oauth.Scopes, returnTo *url.URL) {
	csrf := s.ensureCSRF(w, r, realm.Name)
	renderTemplate(w, consentTemplate, map[string]any{
		"Title":             "Authorize",
		"ClientName":        client.Name,
		"Username":          user.Username,
		"ScopeDescriptions": scopeDescriptions(scopes),
		"Action":            "/realms/" + realm.Name + "/consent",
		"ReturnTo":          returnTo.String(),
		"CSRF":              csrf,
	})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	realm, ok := s.realm(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		s.writePageError(w, http.StatusBadRequest, "Invalid request", "Malformed form submission.")
		return
	}
	returnTo, rtOK := validReturnTo(realm.Name, r.PostFormValue("return_to"))
	if !rtOK {
		s.writePageError(w, http.StatusBadRequest, "Invalid request", "Invalid return address.")
		return
	}
	// The authorize flow names a client; the device flow does not. When a
	// client_id is present it must resolve (its name is shown on the form).
	client := storage.Client{Name: "Meridian"}
	if cid := returnTo.Query().Get("client_id"); cid != "" {
		c, err := s.cfg.Store.Clients().Get(ctx, realm.Name, cid)
		if err != nil {
			s.writePageError(w, http.StatusBadRequest, "Invalid request", "Unknown client.")
			return
		}
		client = c
	}
	if !s.checkCSRF(r, realm.Name) {
		s.renderLogin(w, r, realm, client, returnTo, "Your session expired. Please try again.")
		return
	}

	username := strings.TrimSpace(r.PostFormValue("username"))
	pass := r.PostFormValue("password")
	ip := remoteIP(r, s.cfg.TrustProxyHeaders)

	if !s.cfg.Guard.Allow(ctx, realm.Name, username, ip) {
		// Deliberately the same body as a failed login plus a hint — no
		// oracle about whether the account exists or is locked.
		s.renderLogin(w, r, realm, client, returnTo, "Too many attempts. Try again later.")
		return
	}

	user, uerr := s.cfg.Store.Users().GetByUsername(ctx, realm.Name, username)
	verified := false
	if uerr == nil && !user.Disabled {
		verified, _ = password.Verify(pass, user.PasswordHash)
	} else {
		// Equalize timing for unknown users: verify against a real hash.
		_, _ = password.Verify(pass, dummyHash)
	}
	if !verified {
		s.cfg.Guard.RecordFailure(ctx, realm.Name, username, ip)
		s.renderLogin(w, r, realm, client, returnTo, "Incorrect username or password.")
		return
	}
	s.cfg.Guard.RecordSuccess(ctx, realm.Name, username, ip)
	// Transparent hash upgrade: this is the only moment the plaintext is in
	// hand, so hashes minted under older (weaker) parameters get rewritten
	// here. Best-effort — the login proceeds either way.
	if password.NeedsRehash(user.PasswordHash, password.Default) {
		if h, err := password.Hash(pass, password.Default); err == nil {
			user.PasswordHash = h
			user.UpdatedAt = time.Now()
			_ = s.cfg.Store.Users().Update(ctx, user)
		}
	}
	if err := s.establishSession(w, r, realm, user.ID); err != nil {
		s.writePageError(w, http.StatusInternalServerError, "Error", "Could not establish a session.")
		return
	}
	// The session we just created satisfies any max_age, so drop it from the
	// return URL. Left in, the freshness check at /authorize re-runs against a
	// session created moments ago — and with the legal max_age=0 the strict
	// `elapsed > 0` comparison is never satisfiable, looping the login form
	// forever with no error and no log signal.
	q := returnTo.Query()
	q.Del("max_age")
	returnTo.RawQuery = q.Encode()
	http.Redirect(w, r, stripPrompt(returnTo, "login"), http.StatusSeeOther)
}

// dummyHash is a valid Argon2id hash of an unguessable value, used to keep
// unknown-user logins on the same code path as real ones.
var dummyHash = func() string {
	h, err := password.Hash(secrets.New("timing-equalizer-"), password.Default)
	if err != nil {
		panic(err)
	}
	return h
}()

func (s *Server) handleConsent(w http.ResponseWriter, r *http.Request) {
	realm, ok := s.realm(w, r)
	if !ok {
		return
	}
	ctx := r.Context()
	if err := r.ParseForm(); err != nil {
		s.writePageError(w, http.StatusBadRequest, "Invalid request", "Malformed form submission.")
		return
	}
	returnTo, rtOK := validReturnTo(realm.Name, r.PostFormValue("return_to"))
	if !rtOK {
		s.writePageError(w, http.StatusBadRequest, "Invalid request", "Invalid return address.")
		return
	}
	if !s.checkCSRF(r, realm.Name) {
		s.writePageError(w, http.StatusForbidden, "Session expired", "Please retry the authorization.")
		return
	}
	sess, user, err := s.currentSession(r, realm)
	_ = sess
	if err != nil {
		// Session evaporated mid-consent: restart the flow.
		http.Redirect(w, r, returnTo.String(), http.StatusSeeOther)
		return
	}
	rq := returnTo.Query()
	client, cerr := s.cfg.Store.Clients().Get(ctx, realm.Name, rq.Get("client_id"))
	if cerr != nil {
		s.writePageError(w, http.StatusBadRequest, "Invalid request", "Unknown client.")
		return
	}
	scopes := oauth.ParseScopes(rq.Get("scope"))

	if r.PostFormValue("decision") != "allow" {
		// Denial goes back to the client — redirect_uri revalidated first.
		redirectURI := rq.Get("redirect_uri")
		if redirectURI == "" && len(client.RedirectURIs) == 1 {
			redirectURI = client.RedirectURIs[0]
		}
		if client.AllowsRedirect(redirectURI) {
			if ru, perr := url.Parse(redirectURI); perr == nil {
				oauth.RedirectError(w, r, ru, oauth.E(oauth.ErrAccessDenied, "user denied the request"), rq.Get("state"))
				return
			}
		}
		s.writePageError(w, http.StatusOK, "Request denied", "You denied the authorization request.")
		return
	}

	now := s.now()
	if err := s.cfg.Store.Consents().Upsert(ctx, storage.Consent{
		RealmName: realm.Name,
		UserID:    user.ID,
		ClientID:  client.ClientID,
		Scopes:    scopes,
		GrantedAt: now,
		UpdatedAt: now,
	}); err != nil {
		s.writePageError(w, http.StatusInternalServerError, "Error", "Could not record consent.")
		return
	}
	http.Redirect(w, r, stripPrompt(returnTo, "consent"), http.StatusSeeOther)
}
