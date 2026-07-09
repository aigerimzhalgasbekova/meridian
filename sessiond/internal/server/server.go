// Package server exposes the session store over HTTP.
//
// Trust model: two audiences.
//   - Services (APITokens): the /v1 session API. sessiond is an internal
//     backend — callers are other platform services (idp, portal), never
//     browsers, so the API is bearer-token authenticated like keysmith's.
//   - Browsers (demo only): a server-rendered login demo at /demo that
//     exercises the same store through a session cookie, showing
//     login → protected page → logout-everywhere.
package server

import (
	"log/slog"
	"net/http"

	"github.com/aikazzh/portfolio/sessiond/internal/store"
)

// Config configures the HTTP service.
type Config struct {
	// APITokens authenticate services allowed to manage sessions.
	APITokens []string
	// EnableDemo mounts the browser demo under /demo.
	EnableDemo bool
	Logger     *slog.Logger
}

// Server is the sessiond HTTP service.
type Server struct {
	store   *store.Store
	cfg     Config
	handler http.Handler
}

// New builds the server around a session store.
func New(st *store.Store, cfg Config) *Server {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &Server{store: st, cfg: cfg}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	api := bearerAuth(cfg.APITokens...)
	mux.Handle("POST /v1/sessions", api(http.HandlerFunc(s.handleCreate)))
	mux.Handle("POST /v1/sessions/validate", api(http.HandlerFunc(s.handleValidate)))
	mux.Handle("POST /v1/sessions/rotate", api(http.HandlerFunc(s.handleRotate)))
	mux.Handle("POST /v1/sessions/revoke", api(http.HandlerFunc(s.handleRevoke)))
	mux.Handle("GET /v1/users/{realm}/{user}/sessions", api(http.HandlerFunc(s.handleList)))
	mux.Handle("DELETE /v1/users/{realm}/{user}/sessions", api(http.HandlerFunc(s.handleRevokeUser)))

	if cfg.EnableDemo {
		s.mountDemo(mux)
	}

	s.handler = withObservability(cfg.Logger, mux)
	return s
}

// Handler returns the root http.Handler.
func (s *Server) Handler() http.Handler { return s.handler }
