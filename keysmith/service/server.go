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
func New(manager *keystore.Manager, ks keystore.Config, cfg Config) (*Server, error) {
	if cfg.DefaultAlg == "" {
		cfg.DefaultAlg = jose.AlgEdDSA
	}
	if !cfg.DefaultAlg.Supported() {
		return nil, fmt.Errorf("service: unsupported default algorithm %q", cfg.DefaultAlg)
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
