// Package service exposes the keystore over HTTP: a signing API for trusted
// services, a public JWKS document for verifiers, and an admin surface for
// key lifecycle operations.
//
// Trust model: three audiences, three authentication classes.
//   - Verifiers (public): GET /.well-known/jwks.json — public keys only.
//   - Signers (SignerTokens): POST /v1/sign, /v1/verify.
//   - Operators (AdminTokens): key listing and lifecycle mutation.
package service

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/aikazzh/portfolio/keysmith/jose"
	"github.com/aikazzh/portfolio/keysmith/keystore"
)

// Config configures the HTTP service.
type Config struct {
	// SignerTokens authenticate services allowed to request signatures.
	SignerTokens []string
	// AdminTokens authenticate key lifecycle operators.
	AdminTokens []string

	// DefaultAlg is used when a sign request names no algorithm.
	DefaultAlg jose.Algorithm
	// MaxTokenTTL caps requested token lifetimes (default 1h). Must not
	// exceed the keystore's RetireAfter or rotated-out keys could strand
	// live tokens.
	MaxTokenTTL time.Duration
	// JWKSMaxAge is the Cache-Control max-age for the JWKS document. Must
	// be comfortably below the keystore's PendingDwell so verifier caches
	// refresh before a pending key starts signing.
	JWKSMaxAge time.Duration

	// Now supplies the clock; defaults to time.Now.
	Now func() time.Time

	Logger *slog.Logger
}

// Server is the keysmith HTTP service.
type Server struct {
	manager *keystore.Manager
	cfg     Config
	handler http.Handler
}

// New validates cfg against the keystore configuration and builds the server.
//
// ponytail: the ks parameter is ignored — the invariants below are checked
// against manager.Config(), the configuration the manager actually holds, so
// they cannot be satisfied on paper by a caller passing a different or stale
// value. It stays in the signature only so callers in sibling modules keep
// compiling; delete the parameter once they are updated.
func New(manager *keystore.Manager, _ keystore.Config, cfg Config) (*Server, error) {
	ks := manager.Config()
	if cfg.DefaultAlg == "" {
		cfg.DefaultAlg = jose.AlgEdDSA
	}
	if !cfg.DefaultAlg.Supported() {
		return nil, fmt.Errorf("service: unsupported default algorithm %q", cfg.DefaultAlg)
	}
	// The manager only maintains an active key for algorithms it was configured
	// with, and both /healthz and the /v1/sign fallback resolve DefaultAlg — a
	// mismatch boots cleanly and then 503s forever.
	if !slices.Contains(ks.Algorithms, cfg.DefaultAlg) {
		return nil, fmt.Errorf("service: DefaultAlg %q is not one of the keystore algorithms %v",
			cfg.DefaultAlg, ks.Algorithms)
	}
	if cfg.MaxTokenTTL == 0 {
		cfg.MaxTokenTTL = time.Hour
	}
	if cfg.MaxTokenTTL > ks.RetireAfter {
		return nil, fmt.Errorf("service: MaxTokenTTL %v exceeds keystore RetireAfter %v: rotated keys would strand live tokens",
			cfg.MaxTokenTTL, ks.RetireAfter)
	}
	if cfg.JWKSMaxAge == 0 {
		cfg.JWKSMaxAge = 5 * time.Minute
	}
	if cfg.JWKSMaxAge > ks.PendingDwell/2 {
		return nil, fmt.Errorf("service: JWKSMaxAge %v must be at most half of keystore PendingDwell %v so verifier caches warm before promotion",
			cfg.JWKSMaxAge, ks.PendingDwell)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	s := &Server{manager: manager, cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)

	signer := bearerAuth(cfg.SignerTokens...)
	mux.Handle("POST /v1/sign", signer(http.HandlerFunc(s.handleSign)))
	mux.Handle("POST /v1/verify", signer(http.HandlerFunc(s.handleVerify)))

	admin := bearerAuth(cfg.AdminTokens...)
	mux.Handle("GET /v1/keys", admin(http.HandlerFunc(s.handleListKeys)))
	mux.Handle("POST /v1/keys/generate", admin(http.HandlerFunc(s.handleGenerate)))
	mux.Handle("POST /v1/keys/{id}/promote", admin(http.HandlerFunc(s.handlePromote)))
	mux.Handle("POST /v1/keys/{id}/revoke", admin(http.HandlerFunc(s.handleRevoke)))

	s.handler = withObservability(cfg.Logger, mux)
	return s, nil
}

// Handler returns the root http.Handler.
func (s *Server) Handler() http.Handler { return s.handler }

// RunTicker advances the keystore state machine every interval until ctx ends.
func (s *Server) RunTicker(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.manager.Tick(ctx); err != nil {
				s.cfg.Logger.Error("keystore tick failed", "err", err)
			}
		}
	}
}
