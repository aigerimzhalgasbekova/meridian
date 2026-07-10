// Command consoled runs the Meridian IAM admin console API.
//
// Configuration (environment):
//
//	CONSOLE_ADDR       listen address (default :8085)
//	CONSOLE_HS256_KEY  shared secret for the dev HS256 verifier (required
//	                   unless CONSOLE_DEV_MODE=1, which generates one)
//	CONSOLE_DEV_MODE   "1": seed demo realms/users/sessions/assignments and
//	                   expose GET /v1/dev/tokens with pre-minted persona
//	                   tokens. Never set in production.
//	CONSOLE_WEB_DIR    serve the built SPA (web/dist) from this directory
//
// Production swaps auth.HS256 for a keysmith-JWKS verifier and the MemStore
// for Postgres (users) and a sessiond client (sessions) — the seams are
// server.Config's Verifier, Users, and Sessions fields.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/aikazzh/portfolio/console/internal/auth"
	"github.com/aikazzh/portfolio/console/internal/server"
	"github.com/aikazzh/portfolio/console/rbac"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(logger)
	if err := run(logger); err != nil {
		logger.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	devMode := os.Getenv("CONSOLE_DEV_MODE") == "1"
	key := []byte(os.Getenv("CONSOLE_HS256_KEY"))
	if len(key) == 0 {
		if !devMode {
			return errors.New("CONSOLE_HS256_KEY required (or set CONSOLE_DEV_MODE=1)")
		}
		key = make([]byte, 32)
		if _, err := rand.Read(key); err != nil {
			return err
		}
	}
	verifier := auth.HS256{Key: key}

	engine := rbac.New()
	store := server.NewMemStore()
	cfg := server.Config{
		Engine:   engine,
		Verifier: verifier,
		Users:    store,
		Sessions: store,
		Logger:   logger,
	}

	if devMode {
		logger.Warn("DEV MODE: in-memory stores, seeded demo data, /v1/dev/tokens enabled")
		cfg.DevTokens = seed(engine, store, verifier)
	}

	srv := server.New(cfg)
	var handler http.Handler = srv
	if dir := os.Getenv("CONSOLE_WEB_DIR"); dir != "" {
		handler = withSPA(srv, dir)
	}

	httpSrv := &http.Server{
		Addr:              env("CONSOLE_ADDR", ":8085"),
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.ListenAndServe() }()
	logger.Info("consoled listening", "addr", httpSrv.Addr)

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
}

// withSPA serves API routes from api and everything else from the built SPA,
// with an index.html fallback for client-side routes.
func withSPA(api http.Handler, dir string) http.Handler {
	fs := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/") || r.URL.Path == "/healthz" {
			api.ServeHTTP(w, r)
			return
		}
		if r.URL.Path != "/" {
			if _, err := os.Stat(filepath.Join(dir, filepath.Clean(r.URL.Path))); err != nil {
				http.ServeFile(w, r, filepath.Join(dir, "index.html"))
				return
			}
		}
		fs.ServeHTTP(w, r)
	})
}

// seed populates the demo world: two realms, four personas, a custom role
// with a deny carve-out, users and live sessions. Returns pre-minted tokens.
func seed(e *rbac.Engine, store *server.MemStore, v auth.HS256) map[string]string {
	_ = e.DefineRole(rbac.Role{
		Name:        "support",
		Description: "Operator minus the ability to disable users (deny carve-out demo).",
		Extends:     rbac.RoleOperator,
		Denies:      []rbac.Permission{"users:write"},
	})
	for _, a := range []rbac.Assignment{
		{Subject: "root", Role: rbac.RoleSuperAdmin},
		{Subject: "olivia", Role: rbac.RoleOperator},
		{Subject: "alice", Role: rbac.RoleRealmAdmin, Scope: rbac.Scope{Realm: "engineering"}},
		{Subject: "frank", Role: rbac.RoleRealmAdmin, Scope: rbac.Scope{Realm: "finance"}},
		{Subject: "vera", Role: rbac.RoleViewer},
		{Subject: "sam", Role: "support"},
	} {
		_ = e.Assign(a)
	}
	now := time.Now().UTC()
	for i, u := range []server.User{
		{ID: "u-100", Email: "dana@meridian.dev", Name: "Dana Levin", Realm: "engineering"},
		{ID: "u-101", Email: "eli@meridian.dev", Name: "Eli Ortiz", Realm: "engineering"},
		{ID: "u-102", Email: "fay@meridian.dev", Name: "Fay Chen", Realm: "finance"},
		{ID: "u-103", Email: "gus@meridian.dev", Name: "Gus Adeyemi", Realm: "finance", Disabled: true},
	} {
		store.AddUser(u)
		store.AddSession(server.Session{
			ID:        "sess-" + u.ID,
			UserID:    u.ID,
			CreatedAt: now.Add(-time.Duration(i+1) * time.Hour),
			IP:        "203.0.113.7",
			UserAgent: "Mozilla/5.0 (demo)",
		})
	}
	tokens := make(map[string]string)
	for _, sub := range []string{"root", "olivia", "alice", "frank", "vera", "sam"} {
		tokens[sub] = v.Mint(sub, 24*time.Hour)
	}
	return tokens
}
