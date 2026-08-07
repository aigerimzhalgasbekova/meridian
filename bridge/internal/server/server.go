// Package server is bridge's HTTP surface: the RP-side login and callback
// endpoints, the account-linking flow, the app-facing assertion delivery, the
// server-rendered demo UI, and provider health reporting.
//
// The security-relevant flow lives in /login/{provider} and
// /callback/{provider}; everything else is presentation. See the package docs
// of internal/relay (state/nonce/PKCE), internal/provider (token
// verification), and internal/directory (identity matching) for the rules
// each step enforces.
package server

import (
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/aikazzh/portfolio/bridge/internal/directory"
	"github.com/aikazzh/portfolio/bridge/internal/health"
	"github.com/aikazzh/portfolio/bridge/internal/provider"
	"github.com/aikazzh/portfolio/bridge/internal/relay"
	"github.com/aikazzh/portfolio/keysmith/jose"
)

//go:embed templates/*.html
var templateFS embed.FS

var templates = template.Must(template.ParseFS(templateFS, "templates/*.html"))

// App is a relying application registered with bridge. Assertions are
// delivered only to the exact CallbackURL registered here — the app can never
// steer the redirect (no redirect_uri parameter exists on the app side).
type App struct {
	Name        string
	CallbackURL string
}

// Config configures the Server.
type Config struct {
	// BaseURL is bridge's externally visible base, e.g. http://127.0.0.1:8080.
	// Upstream redirect URIs are derived from it: BaseURL + /callback/{name}.
	BaseURL string
	// Issuer is the iss claim of app-facing assertions (default BaseURL).
	Issuer string
	// HMACKey signs relay state parameters (>= 32 bytes).
	HMACKey []byte
	// Apps maps app ID to its registered callback.
	Apps map[string]App
	// InsecureDev drops the Secure cookie flag for plain-HTTP dev mode.
	InsecureDev bool
	// Logger receives the security audit trail: every callback rejection with
	// its concrete typed error, and every identity provisioned or linked.
	// nil = slog.Default().
	Logger *slog.Logger
	// Now is injectable for tests (nil = time.Now).
	Now func() time.Time
}

// Server wires the registry, directory, relay and signer behind an
// http.Handler.
type Server struct {
	cfg      Config
	reg      *provider.Registry
	dir      directory.Store
	relay    *relay.Manager
	signer   Signer
	sessions *sessions
	mux      *http.ServeMux
}

// New builds a Server.
func New(cfg Config, reg *provider.Registry, dir directory.Store, signer Signer) (*Server, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("server: BaseURL is required")
	}
	if cfg.Issuer == "" {
		cfg.Issuer = cfg.BaseURL
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	rm, err := relay.NewManager(cfg.HMACKey, cfg.Now)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:      cfg,
		reg:      reg,
		dir:      dir,
		relay:    rm,
		signer:   signer,
		sessions: newSessions(cfg.Now),
		mux:      http.NewServeMux(),
	}
	s.mux.HandleFunc("GET /{$}", s.handleHome)
	s.mux.HandleFunc("GET /login/{provider}", s.handleLogin)
	s.mux.HandleFunc("GET /callback/{provider}", s.handleCallback)
	s.mux.HandleFunc("POST /link/{provider}", s.handleLink)
	s.mux.HandleFunc("GET /account", s.handleAccount)
	s.mux.HandleFunc("POST /logout", s.handleLogout)
	// Liveness: always 200 while the process serves. Provider readiness is
	// deliberately separate — an upstream IdP outage must not make a load
	// balancer recycle otherwise-healthy bridge tasks.
	s.mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
	})
	s.mux.HandleFunc("GET /healthz/providers", s.handleProviderHealth)
	return s, nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) { s.mux.ServeHTTP(w, r) }

func (s *Server) redirectURI(providerName string) string {
	return s.cfg.BaseURL + "/callback/" + providerName
}

// providerView is what templates render per provider.
type providerView struct {
	Name        string
	DisplayName string
	Healthy     bool
}

func (s *Server) providerViews() []providerView {
	var out []providerView
	for _, p := range s.reg.All() {
		cfg := p.Config()
		out = append(out, providerView{Name: cfg.Name, DisplayName: cfg.DisplayName, Healthy: p.Healthy()})
	}
	return out
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := templates.ExecuteTemplate(w, name, data); err != nil {
		// Headers are already on the wire, so the response cannot be salvaged;
		// all that is left is to say so.
		s.cfg.Logger.Error("template render failed", "template", name, "err", err)
	}
}

// handleHome renders the provider picker.
func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	_, signedIn := s.currentSession(r)
	appID := r.URL.Query().Get("app")
	if appID != "" {
		if _, ok := s.cfg.Apps[appID]; !ok {
			http.Error(w, "unknown app", http.StatusBadRequest)
			return
		}
	}
	s.render(w, http.StatusOK, "home.html", map[string]any{
		"Providers": s.providerViews(),
		"SignedIn":  signedIn,
		"App":       appID,
	})
}

// handleLogin begins a login flow: HMAC state + nonce + PKCE, then a redirect
// to the upstream authorization endpoint. When the provider's breaker is open
// it fails fast with a page listing healthy alternates instead of letting the
// user wait out a dead upstream.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	p := s.reg.Get(r.PathValue("provider"))
	if p == nil {
		http.NotFound(w, r)
		return
	}
	appID := r.URL.Query().Get("app")
	if appID != "" {
		if _, ok := s.cfg.Apps[appID]; !ok {
			http.Error(w, "unknown app", http.StatusBadRequest)
			return
		}
	}
	if !p.Healthy() {
		s.renderUnavailable(w, p)
		return
	}
	flow, state, err := s.relay.Begin(p.Config().Name, relay.ModeLogin, appID, "")
	if err != nil {
		s.beginFailed(w, p, err)
		return
	}
	authURL, err := p.AuthorizeURL(r.Context(), state, flow.Nonce, relay.Challenge(flow.Verifier), s.redirectURI(p.Config().Name))
	if err != nil {
		s.upstreamError(w, p, err)
		return
	}
	s.setFlowCookie(w, p.Config().Name, flow.Binding)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// beginFailed reports a flow that could not be started. A full flow table is
// load shedding, not a bug: say "busy", not "broken".
func (s *Server) beginFailed(w http.ResponseWriter, p *provider.Provider, err error) {
	s.cfg.Logger.Warn("flow could not be started", "provider", p.Config().Name, "err", err)
	if errors.Is(err, relay.ErrTooBusy) {
		s.render(w, http.StatusServiceUnavailable, "error.html", map[string]any{
			"Message": "Too many sign-ins are in progress. Try again in a moment.",
		})
		return
	}
	http.Error(w, "internal error", http.StatusInternalServerError)
}

// handleLink begins a link flow: attach another provider to the signed-in
// identity. It demands a fresh upstream authentication on the current session
// (a stolen long-lived cookie must not be enough to graft an attacker's
// account onto the victim's identity) and, by construction of the flow, a
// fresh authentication to the provider being linked.
func (s *Server) handleLink(w http.ResponseWriter, r *http.Request) {
	p := s.reg.Get(r.PathValue("provider"))
	if p == nil {
		http.NotFound(w, r)
		return
	}
	sess, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	if s.cfg.Now().Sub(sess.AuthTime) > linkFreshness {
		s.render(w, http.StatusForbidden, "reauth.html", map[string]any{
			"Provider": sess.Provider,
		})
		return
	}
	if !p.Healthy() {
		s.renderUnavailable(w, p)
		return
	}
	flow, state, err := s.relay.Begin(p.Config().Name, relay.ModeLink, "", sess.ID)
	if err != nil {
		s.beginFailed(w, p, err)
		return
	}
	authURL, err := p.AuthorizeURL(r.Context(), state, flow.Nonce, relay.Challenge(flow.Verifier), s.redirectURI(p.Config().Name))
	if err != nil {
		s.upstreamError(w, p, err)
		return
	}
	s.setFlowCookie(w, p.Config().Name, flow.Binding)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleCallback is the upstream redirect target: validate state (one-time,
// HMAC, expiry, provider binding), exchange the code, fully verify the ID
// token, then provision/link and hand off.
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	p := s.reg.Get(r.PathValue("provider"))
	if p == nil {
		http.NotFound(w, r)
		return
	}
	pname := p.Config().Name
	// The flow is single-use whatever happens next, so the binding cookie is
	// spent on every exit path from here on.
	s.clearFlowCookie(w, pname)
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		s.cfg.Logger.Warn("upstream reported an error at the callback",
			"provider", pname, "error", e, "remote", r.RemoteAddr)
		s.render(w, http.StatusBadGateway, "error.html", map[string]any{
			"Message": "The identity provider reported an error: " + e,
		})
		return
	}
	flow, err := s.relay.Consume(q.Get("state"), pname, flowBinding(r))
	if err != nil {
		// Deliberately uniform to the caller: replay, tamper, expiry and a
		// callback presented by the wrong browser all read the same. The
		// distinct error goes to the log, which is where it is useful.
		s.cfg.Logger.Warn("callback state rejected",
			"provider", pname, "err", err, "remote", r.RemoteAddr)
		s.render(w, http.StatusBadRequest, "error.html", map[string]any{
			"Message": "This sign-in link is invalid or has already been used. Start again.",
		})
		return
	}
	code := q.Get("code")
	if code == "" {
		s.cfg.Logger.Warn("callback without an authorization code", "provider", pname, "remote", r.RemoteAddr)
		s.render(w, http.StatusBadRequest, "error.html", map[string]any{"Message": "Missing authorization code."})
		return
	}
	rawToken, err := p.Exchange(r.Context(), code, flow.Verifier, s.redirectURI(p.Config().Name))
	if err != nil {
		s.upstreamError(w, p, err)
		return
	}
	claims, err := p.VerifyIDToken(r.Context(), rawToken, flow.Nonce)
	if err != nil {
		s.cfg.Logger.Warn("ID token failed verification",
			"provider", pname, "err", err, "remote", r.RemoteAddr)
		s.render(w, http.StatusUnauthorized, "error.html", map[string]any{
			"Message": "The identity token failed verification.",
		})
		return
	}
	email, _ := claims.Extra["email"].(string)
	if !claimTrue(claims.Extra["email_verified"]) {
		// OIDC Core §5.7: an unverified upstream email is attacker-chosen.
		// ADR 0001 already refuses to *match* on it; we must not record it or
		// forward it downstream as an authenticated attribute either — an app
		// that keys accounts on the email claim would be trivially takeoverable.
		email = ""
	}
	name, _ := claims.Extra["name"].(string)
	link := directory.Link{Provider: p.Config().Name, Subject: claims.Subject, Email: email}

	switch flow.Mode {
	case relay.ModeLink:
		s.finishLink(w, r, flow, link)
	default:
		s.finishLogin(w, r, flow, link, email, name)
	}
}

// finishLogin resolves the upstream identity to a local one — by (provider,
// subject) only, JIT-provisioning on first contact — then establishes a
// session and hands off to the app or the account page.
func (s *Server) finishLogin(w http.ResponseWriter, r *http.Request, flow relay.Flow, link directory.Link, email, name string) {
	ident, err := s.dir.IdentityByLink(link.Provider, link.Subject)
	if errors.Is(err, directory.ErrNotFound) {
		ident, err = s.dir.CreateIdentity(email, name, link)
		if err == nil {
			s.cfg.Logger.Info("identity provisioned",
				"identity", ident.ID, "provider", link.Provider, "subject", link.Subject)
		}
	}
	if err != nil {
		s.cfg.Logger.Error("identity resolution failed", "provider", link.Provider, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	sess := s.sessions.create(ident.ID, link.Provider)
	s.setSessionCookie(w, sess)

	if flow.AppID != "" {
		s.deliverAssertion(w, r, flow.AppID, ident, link.Provider)
		return
	}
	http.Redirect(w, r, "/account", http.StatusFound)
}

// finishLink attaches the freshly authenticated upstream account to the
// identity of the session that initiated the link flow. The browser
// completing the flow must *be* the session that started it — not merely hold
// a callback for it — and that session's own upstream authentication must
// still be fresh: fresh auth to *both* sides, not one.
func (s *Server) finishLink(w http.ResponseWriter, r *http.Request, flow relay.Flow, link directory.Link) {
	// currentSession resolves the requesting browser's own cookie and already
	// enforces session expiry, so comparing its ID to the flow's covers both
	// "session still alive" and "same party that started the link".
	sess, ok := s.currentSession(r)
	if !ok || sess.ID != flow.SessionID || s.cfg.Now().Sub(sess.AuthTime) > linkFreshness {
		s.cfg.Logger.Warn("link callback rejected",
			"provider", link.Provider, "session_matched", ok && sess.ID == flow.SessionID, "remote", r.RemoteAddr)
		s.render(w, http.StatusForbidden, "error.html", map[string]any{
			"Message": "Your session expired during linking. Sign in again and retry.",
		})
		return
	}
	if err := s.dir.AddLink(sess.IdentityID, link); err != nil {
		msg := "Linking failed."
		if errors.Is(err, directory.ErrAlreadyLinked) {
			msg = "That account is already linked to an identity. Bridge never merges identities automatically — see the account page."
		}
		s.cfg.Logger.Warn("link refused",
			"identity", sess.IdentityID, "provider", link.Provider, "err", err)
		s.render(w, http.StatusConflict, "error.html", map[string]any{"Message": msg})
		return
	}
	s.cfg.Logger.Info("provider linked",
		"identity", sess.IdentityID, "provider", link.Provider, "subject", link.Subject)
	s.sessions.refresh(sess.ID, link.Provider)
	http.Redirect(w, r, "/account", http.StatusFound)
}

// deliverAssertion mints the short-lived app-facing JWT and redirects to the
// app's registered callback — the exact URL from configuration, never a
// request parameter.
func (s *Server) deliverAssertion(w http.ResponseWriter, r *http.Request, appID string, ident directory.Identity, idp string) {
	app, ok := s.cfg.Apps[appID]
	if !ok {
		http.Error(w, "unknown app", http.StatusBadRequest)
		return
	}
	now := s.cfg.Now()
	token, err := s.signer.Sign(jose.Claims{
		Issuer:    s.cfg.Issuer,
		Subject:   ident.ID,
		Audience:  []string{appID},
		ExpiresAt: now.Add(AssertionTTL).Unix(),
		IssuedAt:  now.Unix(),
		Extra: map[string]any{
			"email": ident.Email,
			// Only upstream-verified emails are ever recorded, so a present
			// email is a verified one. Stated explicitly so relying apps do
			// not have to assume it.
			"email_verified": ident.Email != "",
			"name":           ident.Name,
			"idp":            idp,
			"amr":            []string{"federated"},
		},
	})
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	u, err := url.Parse(app.CallbackURL)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	qq := u.Query()
	qq.Set("assertion", token)
	u.RawQuery = qq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// handleAccount renders the signed-in identity, its linked providers, unlinked
// providers it could link, and — as a hint only — other local identities that
// recorded the same email. Bridge surfaces that collision and offers linking;
// it never merges on its own (docs/adr/0001).
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	sess, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	ident, err := s.dir.Identity(sess.IdentityID)
	if err != nil {
		s.clearSessionCookie(w)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	links, _ := s.dir.Links(ident.ID)
	linked := make(map[string]bool, len(links))
	for _, l := range links {
		linked[l.Provider] = true
	}
	var linkable []providerView
	for _, pv := range s.providerViews() {
		if !linked[pv.Name] {
			linkable = append(linkable, pv)
		}
	}
	var collisions []directory.Identity
	sameEmail, _ := s.dir.IdentitiesByEmail(ident.Email)
	for _, other := range sameEmail {
		if other.ID != ident.ID {
			collisions = append(collisions, other)
		}
	}
	canLink := s.cfg.Now().Sub(sess.AuthTime) <= linkFreshness
	s.render(w, http.StatusOK, "account.html", map[string]any{
		"Identity":   ident,
		"Links":      links,
		"Linkable":   linkable,
		"Collisions": collisions,
		"CanLink":    canLink,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(sessionCookie); err == nil {
		s.sessions.delete(c.Value)
	}
	s.clearSessionCookie(w)
	http.Redirect(w, r, "/", http.StatusFound)
}

// handleProviderHealth exposes per-provider breaker state as JSON.
func (s *Server) handleProviderHealth(w http.ResponseWriter, r *http.Request) {
	type entry struct {
		Provider string       `json:"provider"`
		State    health.State `json:"state"`
		Healthy  bool         `json:"healthy"`
	}
	var out []entry
	allHealthy := true
	for _, p := range s.reg.All() {
		h := p.Healthy()
		allHealthy = allHealthy && h
		out = append(out, entry{Provider: p.Config().Name, State: p.Breaker().State(), Healthy: h})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Provider < out[j].Provider })
	w.Header().Set("Content-Type", "application/json")
	if !allHealthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	json.NewEncoder(w).Encode(map[string]any{"providers": out})
}

// renderUnavailable is the fail-fast page: this provider is down, here are the
// ones that aren't.
func (s *Server) renderUnavailable(w http.ResponseWriter, p *provider.Provider) {
	var alternates []providerView
	for _, pv := range s.providerViews() {
		if pv.Healthy && pv.Name != p.Config().Name {
			alternates = append(alternates, pv)
		}
	}
	s.render(w, http.StatusServiceUnavailable, "unavailable.html", map[string]any{
		"Provider":   p.Config().DisplayName,
		"Alternates": alternates,
	})
}

// upstreamError maps an upstream failure mid-flow: breaker-open gets the
// fail-fast page, anything else a generic upstream error.
func (s *Server) upstreamError(w http.ResponseWriter, p *provider.Provider, err error) {
	// The last silent rejection path: a failed code exchange (stolen or injected
	// code, PKCE mismatch, dead token endpoint) and every breaker-open refusal
	// land here. Provider errors carry no code, token or state bytes.
	s.cfg.Logger.Warn("upstream call failed", "provider", p.Config().Name, "err", err)
	if errors.Is(err, health.ErrOpen) {
		s.renderUnavailable(w, p)
		return
	}
	s.render(w, http.StatusBadGateway, "error.html", map[string]any{
		"Message": "The identity provider could not be reached. Try again shortly.",
	})
}

// claimTrue reads a boolean OIDC claim. Providers are inconsistent about the
// JSON type — Google sends a bool, some send the string "true" — so accept
// both and treat anything else (including absent) as false.
func claimTrue(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t == "true"
	}
	return false
}
