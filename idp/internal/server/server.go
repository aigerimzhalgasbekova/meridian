// Package server implements the idp HTTP surface: OAuth 2.0 / OIDC protocol
// endpoints, login and consent UI, and dynamic client registration.
//
// Route map (all realm-scoped under /realms/{realm}):
//
//	GET  /.well-known/openid-configuration    discovery (RFC 8414 + OIDC)
//	GET  /.well-known/jwks.json               verification keys (proxied from keysmith)
//	GET  /authorize                           authorization endpoint (code + PKCE)
//	POST /login                               login form submission
//	POST /consent                             consent form submission
//	POST /token                               token endpoint (4 grant types)
//	GET/POST /userinfo                        OIDC userinfo
//	POST /introspect                          RFC 7662 introspection
//	POST /revoke                              RFC 7009 revocation
//	POST /device/code                         RFC 8628 device authorization
//	GET  /device                              user code entry page
//	POST /device                              user code approval/denial
//	POST /register                            RFC 7591 dynamic client registration
//	POST /logout                              end idp session
package server

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/aikazzh/portfolio/idp/internal/storage"
	"github.com/aikazzh/portfolio/idp/internal/token"
	ksclient "github.com/aikazzh/portfolio/keysmith/client"
)

// LoginGuard rate-limits and audits authentication attempts. The default is a
// local fixed-window limiter; deployments wire this to sentinel.
type LoginGuard interface {
	// Allow reports whether a login attempt may proceed.
	Allow(ctx context.Context, realm, username, remoteIP string) bool
	// RecordFailure notes a failed attempt.
	RecordFailure(ctx context.Context, realm, username, remoteIP string)
	// RecordSuccess notes a successful attempt (resets counters).
	RecordSuccess(ctx context.Context, realm, username, remoteIP string)
}

// Config assembles a Server.
type Config struct {
	// BaseURL is the public origin (https://idp.example). Issuer URLs,
	// redirects, and cookies derive from it.
	BaseURL string
	Store   storage.Store
	Signer  token.Signer
	// Keysmith verifies access tokens (userinfo, introspection) and serves
	// the JWKS document this server re-publishes per realm.
	Keysmith *ksclient.Client
	Guard    LoginGuard
	Logger   *slog.Logger
	// RegistrationToken gates RFC 7591 dynamic client registration.
	// Empty disables the endpoint.
	RegistrationToken string
	// InsecureDev drops the Secure cookie attribute for plain-HTTP local dev.
	InsecureDev bool
	Now         func() time.Time
}

// Server is the idp HTTP server.
type Server struct {
	cfg     Config
	issuer  *token.Issuer
	handler http.Handler
}

// AuthCodeTTL is the RFC 6749 §4.1.2-recommended short code lifetime.
const AuthCodeTTL = 60 * time.Second

// New builds the server.
func New(cfg Config) (*Server, error) {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Guard == nil {
		cfg.Guard = NewLocalGuard(cfg.Now)
	}
	s := &Server{
		cfg:    cfg,
		issuer: &token.Issuer{BaseURL: cfg.BaseURL, Signer: cfg.Signer, Now: cfg.Now},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /realms/{realm}/.well-known/openid-configuration", s.handleDiscovery)
	mux.HandleFunc("GET /realms/{realm}/.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("GET /realms/{realm}/authorize", s.handleAuthorize)
	mux.HandleFunc("POST /realms/{realm}/login", s.handleLogin)
	mux.HandleFunc("POST /realms/{realm}/consent", s.handleConsent)
	mux.HandleFunc("POST /realms/{realm}/token", s.handleToken)
	mux.HandleFunc("GET /realms/{realm}/userinfo", s.handleUserinfo)
	mux.HandleFunc("POST /realms/{realm}/userinfo", s.handleUserinfo)
	mux.HandleFunc("POST /realms/{realm}/introspect", s.handleIntrospect)
	mux.HandleFunc("POST /realms/{realm}/revoke", s.handleRevoke)
	mux.HandleFunc("POST /realms/{realm}/device/code", s.handleDeviceCode)
	mux.HandleFunc("GET /realms/{realm}/device", s.handleDevicePage)
	mux.HandleFunc("POST /realms/{realm}/device", s.handleDeviceSubmit)
	mux.HandleFunc("POST /realms/{realm}/register", s.handleRegister)
	mux.HandleFunc("POST /realms/{realm}/logout", s.handleLogout)

	s.handler = withRequestLog(cfg.Logger, withSecurityHeaders(mux))
	return s, nil
}

// Handler returns the root handler.
func (s *Server) Handler() http.Handler { return s.handler }

func (s *Server) now() time.Time { return s.cfg.Now() }

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// realm loads the realm named in the path, or writes a 404.
func (s *Server) realm(w http.ResponseWriter, r *http.Request) (storage.Realm, bool) {
	realm, err := s.cfg.Store.Realms().Get(r.Context(), r.PathValue("realm"))
	if err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown_realm"})
		return storage.Realm{}, false
	}
	return realm, true
}
