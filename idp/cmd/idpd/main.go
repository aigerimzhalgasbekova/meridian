// Command idpd runs the Meridian OAuth 2.0 / OIDC authorization server.
//
// Configuration (environment):
//
//	IDP_ADDR                listen address (default :8080)
//	IDP_BASE_URL            public origin (default http://localhost:8080)
//	IDP_KEYSMITH_URL        keysmith base URL (default http://localhost:8081)
//	IDP_KEYSMITH_TOKEN      keysmith signer token
//	IDP_REGISTRATION_TOKEN  initial access token for RFC 7591 registration (empty = disabled)
//	IDP_DEV_MODE            "1": in-memory storage, seeded demo realm, insecure cookies
//	IDP_DATABASE_URL        Postgres DSN (required unless IDP_DEV_MODE=1)
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aikazzh/portfolio/idp/internal/server"
	"github.com/aikazzh/portfolio/idp/internal/storage"
	"github.com/aikazzh/portfolio/idp/internal/storage/memory"
	"github.com/aikazzh/portfolio/idp/internal/storage/postgres"
	ksclient "github.com/aikazzh/portfolio/keysmith/client"
	"github.com/aikazzh/portfolio/keysmith/jose"
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

	devMode := os.Getenv("IDP_DEV_MODE") == "1"
	var store storage.Store
	switch {
	case devMode:
		logger.Warn("DEV MODE: in-memory storage with seeded demo data")
		store = memory.New()
	default:
		dsn := os.Getenv("IDP_DATABASE_URL")
		if dsn == "" {
			return errors.New("IDP_DATABASE_URL required (or set IDP_DEV_MODE=1)")
		}
		pg, err := postgres.Open(ctx, dsn)
		if err != nil {
			return err
		}
		defer pg.Close()
		if err := pg.Migrate(ctx); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
		store = pg
	}

	ks := ksclient.New(env("IDP_KEYSMITH_URL", "http://localhost:8081"), os.Getenv("IDP_KEYSMITH_TOKEN"))
	srv, err := server.New(server.Config{
		BaseURL:           env("IDP_BASE_URL", "http://localhost:8080"),
		Store:             store,
		Signer:            &keysmithSigner{ks},
		Keysmith:          ks,
		Logger:            logger,
		RegistrationToken: os.Getenv("IDP_REGISTRATION_TOKEN"),
		InsecureDev:       devMode,
	})
	if err != nil {
		return err
	}
	if devMode {
		if err := server.SeedDev(ctx, store); err != nil {
			return fmt.Errorf("seed dev data: %w", err)
		}
		logger.Info("seeded demo realm", "realm", "demo", "user", "alice", "password", "password123")
	}

	httpSrv := &http.Server{
		Addr:              env("IDP_ADDR", ":8080"),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		logger.Info("idpd listening", "addr", httpSrv.Addr)
		if err := httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutdownCtx)
}

// keysmithSigner adapts the keysmith client to the token.Signer interface.
type keysmithSigner struct {
	c *ksclient.Client
}

func (k *keysmithSigner) Sign(ctx context.Context, claims jose.Claims, ttl time.Duration) (string, error) {
	return k.c.Sign(ctx, ksclient.SignRequest{Claims: claims, TTLSeconds: int64(ttl.Seconds())})
}
