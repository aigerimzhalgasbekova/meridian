// Command sentineld runs the sentinel adaptive-security decision service.
//
// Configuration (environment):
//
//	SENTINEL_ADDR        listen address (default :8084)
//	SENTINEL_TOKEN       bearer token for /v1 routes (required)
//	SENTINEL_AUDIT_PATH  JSONL audit chain file (default sentinel-audit.jsonl;
//	                     "memory" keeps the chain in RAM for dev)
//	SENTINEL_BAD_IPS     comma-separated known-bad IP list (optional)
package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aikazzh/portfolio/sentinel/audit"
	"github.com/aikazzh/portfolio/sentinel/internal/server"
	"github.com/aikazzh/portfolio/sentinel/lockout"
	"github.com/aikazzh/portfolio/sentinel/ratelimit"
	"github.com/aikazzh/portfolio/sentinel/risk"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(logger); err != nil {
		logger.Error("sentineld exiting", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	token := os.Getenv("SENTINEL_TOKEN")
	if token == "" {
		return errors.New("SENTINEL_TOKEN is required (refusing to start unauthenticated)")
	}
	addr := envOr("SENTINEL_ADDR", ":8084")

	var store audit.Store
	var anchorSink io.Writer
	auditPath := envOr("SENTINEL_AUDIT_PATH", "sentinel-audit.jsonl")
	if auditPath == "memory" {
		store = audit.NewMemStore()
	} else {
		fs, err := audit.OpenFileStore(auditPath)
		if err != nil {
			return err
		}
		defer fs.Close()
		store = fs
		// Out-of-band anchor sidecar for truncation resistance (see audit.Options).
		anchorFile, err := os.OpenFile(auditPath+".anchors", os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		defer anchorFile.Close()
		anchorSink = anchorFile
	}
	log, err := audit.New(store, audit.Options{AnchorEvery: 100, AnchorSink: anchorSink})
	if err != nil {
		return err
	}

	limiter, err := ratelimit.New(ratelimit.NewMemStore(), map[string]ratelimit.Policy{
		// Defaults sized for login traffic; tune per deployment.
		"ip":     {Limit: 100, Window: time.Minute, Burst: 20},
		"user":   {Limit: 20, Window: time.Minute},
		"client": {Limit: 1000, Window: time.Minute},
	}, nil)
	if err != nil {
		return err
	}

	var badIPs []string
	if v := os.Getenv("SENTINEL_BAD_IPS"); v != "" {
		badIPs = strings.Split(v, ",")
	}

	srv := server.New(server.Config{
		Token:    token,
		Limiter:  limiter,
		Lockouts: lockout.New(lockout.Policy{}, nil),
		Risk:     risk.New(risk.Config{Geo: risk.TestFixture, BadIPs: badIPs}),
		Audit:    log,
		Logger:   logger,
	})

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           srv,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.ListenAndServe() }()
	logger.Info("sentineld listening", "addr", addr, "audit", auditPath)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return httpSrv.Shutdown(shutdownCtx)
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
