// Command keysmithd runs the keysmith service.
//
// Configuration is environment-only (12-factor):
//
//	KEYSMITH_ADDR            listen address (default :8081)
//	KEYSMITH_STORE_PATH      encrypted keystore file (default ./keysmith-keys.json)
//	KEYSMITH_MASTER_KEY      base64 (std) 32-byte KEK master key. REQUIRED unless
//	                         KEYSMITH_DEV_MODE=1, which generates an ephemeral
//	                         in-memory store (keys lost on exit — dev only).
//	KEYSMITH_GENERATION_ANCHOR  SSM parameter name holding the keystore's
//	                         current generation. When set, the store refuses to
//	                         open a keystore rolled back below the anchored
//	                         generation (whole-file rollback detection). Unset:
//	                         detection off — dev only.
//	KEYSMITH_SIGNER_TOKENS   comma-separated bearer tokens for the sign API
//	KEYSMITH_ADMIN_TOKENS    comma-separated bearer tokens for the admin API
//	KEYSMITH_ALGS            comma-separated algorithms (default EdDSA,RS256)
//	KEYSMITH_PENDING_DWELL   e.g. 15m (default)
//	KEYSMITH_MAX_KEY_AGE     e.g. 720h (default 30 days)
//	KEYSMITH_RETIRE_AFTER    e.g. 24h (default; must cover max token TTL)
//	KEYSMITH_MAX_TOKEN_TTL   e.g. 1h (default)
//	KEYSMITH_JWKS_MAX_AGE    e.g. 5m (default)
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ssm"

	"github.com/aikazzh/portfolio/keysmith/jose"
	"github.com/aikazzh/portfolio/keysmith/keystore"
	"github.com/aikazzh/portfolio/keysmith/service"
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

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}

func splitList(v string) []string {
	var out []string
	for part := range strings.SplitSeq(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	pendingDwell, err := envDuration("KEYSMITH_PENDING_DWELL", 15*time.Minute)
	if err != nil {
		return err
	}
	maxKeyAge, err := envDuration("KEYSMITH_MAX_KEY_AGE", 30*24*time.Hour)
	if err != nil {
		return err
	}
	retireAfter, err := envDuration("KEYSMITH_RETIRE_AFTER", 24*time.Hour)
	if err != nil {
		return err
	}
	maxTokenTTL, err := envDuration("KEYSMITH_MAX_TOKEN_TTL", time.Hour)
	if err != nil {
		return err
	}
	jwksMaxAge, err := envDuration("KEYSMITH_JWKS_MAX_AGE", 5*time.Minute)
	if err != nil {
		return err
	}

	var algs []jose.Algorithm
	for _, a := range splitList(env("KEYSMITH_ALGS", "EdDSA,RS256")) {
		algs = append(algs, jose.Algorithm(a))
	}

	var store keystore.Store
	switch {
	case os.Getenv("KEYSMITH_DEV_MODE") == "1":
		logger.Warn("DEV MODE: in-memory keystore, keys are ephemeral")
		store = keystore.NewMemoryStore()
	default:
		masterB64 := os.Getenv("KEYSMITH_MASTER_KEY")
		if masterB64 == "" {
			return errors.New("KEYSMITH_MASTER_KEY required (or set KEYSMITH_DEV_MODE=1)")
		}
		master, err := base64.StdEncoding.DecodeString(masterB64)
		if err != nil {
			return fmt.Errorf("KEYSMITH_MASTER_KEY: %w", err)
		}
		kek, err := keystore.NewLocalKEK("local-v1", master)
		if err != nil {
			return err
		}
		var anchor keystore.Anchor
		if name := os.Getenv("KEYSMITH_GENERATION_ANCHOR"); name != "" {
			awsCfg, err := awsconfig.LoadDefaultConfig(ctx)
			if err != nil {
				return fmt.Errorf("KEYSMITH_GENERATION_ANCHOR: load AWS config: %w", err)
			}
			anchor = keystore.NewSSMAnchor(ssm.NewFromConfig(awsCfg), name)
		} else {
			logger.Warn("KEYSMITH_GENERATION_ANCHOR unset: keystore rollback detection disabled")
		}
		fs, err := keystore.OpenFileStore(ctx, env("KEYSMITH_STORE_PATH", "./keysmith-keys.json"), kek, anchor)
		if err != nil {
			return err
		}
		defer fs.Close() // releases the single-writer lock
		store = fs
	}

	auditLog := logger.With("component", "keystore-audit")
	ksCfg := keystore.Config{
		Algorithms:   algs,
		PendingDwell: pendingDwell,
		MaxKeyAge:    maxKeyAge,
		RetireAfter:  retireAfter,
		Audit: func(e keystore.Event) {
			auditLog.Info("key_lifecycle", "op", e.Op, "key_id", e.KeyID, "alg", e.Alg, "detail", e.Detail)
		},
	}
	manager, err := keystore.NewManager(store, ksCfg)
	if err != nil {
		return err
	}
	if err := manager.Tick(ctx); err != nil {
		return fmt.Errorf("bootstrap tick: %w", err)
	}

	srv, err := service.New(manager, ksCfg, service.Config{
		SignerTokens: splitList(os.Getenv("KEYSMITH_SIGNER_TOKENS")),
		AdminTokens:  splitList(os.Getenv("KEYSMITH_ADMIN_TOKENS")),
		// Taken from KEYSMITH_ALGS rather than defaulted, so the service's
		// default algorithm cannot disagree with the keystore's list.
		DefaultAlg:  algs[0],
		MaxTokenTTL: maxTokenTTL,
		JWKSMaxAge:  jwksMaxAge,
		Logger:      logger,
	})
	if err != nil {
		return err
	}
	// The ticker writes the keystore, so it must be done before the deferred
	// fs.Close() releases the single-writer lock and waits on the in-flight
	// anchor advances — a Close racing a persist can trip a WaitGroup misuse
	// panic on the way out. Defers run LIFO, so this one precedes fs.Close().
	tickCtx, stopTicker := context.WithCancel(ctx)
	tickerDone := make(chan struct{})
	go func() {
		defer close(tickerDone)
		srv.RunTicker(tickCtx, time.Minute)
	}()
	defer func() { stopTicker(); <-tickerDone }()

	httpSrv := &http.Server{
		Addr:              env("KEYSMITH_ADDR", ":8081"),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		logger.Info("keysmithd listening", "addr", httpSrv.Addr)
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
