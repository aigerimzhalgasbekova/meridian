// Command sessiond runs the distributed session service.
//
// Configuration is environment-only (12-factor):
//
//	SESSIOND_ADDR          listen address (default :8082)
//	SESSIOND_REDIS_URL     redis URL, e.g. redis://localhost:6379/0. REQUIRED
//	                       unless SESSIOND_DEV_MODE=1, which starts an embedded
//	                       miniredis (sessions lost on exit — dev only).
//	SESSIOND_API_TOKENS    comma-separated bearer tokens for the /v1 API
//	SESSIOND_IDLE_TTL      sliding idle timeout, e.g. 30m (default)
//	SESSIOND_ABSOLUTE_TTL  absolute lifetime cap, e.g. 12h (default)
//	SESSIOND_MAX_PER_USER  concurrent session cap (default 5)
//	SESSIOND_LIMIT_POLICY  evict-oldest (default) or reject
//	SESSIOND_CACHE_TTL     local cache TTL / staleness bound, e.g. 2s (default)
//	SESSIOND_DEMO          (removed) demo mode now follows SESSIOND_DEV_MODE only,
//	                       since it mints unauthenticated sessions and must never
//	                       be reachable against a real Redis.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aikazzh/portfolio/sessiond/internal/server"
	"github.com/aikazzh/portfolio/sessiond/internal/store"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
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

	devMode := os.Getenv("SESSIOND_DEV_MODE") == "1"

	redisURL := os.Getenv("SESSIOND_REDIS_URL")
	if redisURL == "" && !devMode {
		return errors.New("SESSIOND_REDIS_URL required (or set SESSIOND_DEV_MODE=1)")
	}
	// Demo routes mint real sessions without auth, so they may only run against
	// the throwaway embedded store — never a Redis someone pointed at prod.
	embedded := redisURL == ""
	if embedded {
		mr, err := miniredis.Run()
		if err != nil {
			return fmt.Errorf("embedded miniredis: %w", err)
		}
		defer mr.Close()
		logger.Warn("DEV MODE: embedded in-memory redis, sessions are ephemeral")
		redisURL = "redis://" + mr.Addr()
	}
	opts, err := redis.ParseURL(redisURL)
	if err != nil {
		return fmt.Errorf("SESSIOND_REDIS_URL: %w", err)
	}
	rdb := redis.NewClient(opts)
	defer rdb.Close()
	if err := rdb.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("redis ping: %w", err)
	}

	idleTTL, err := envDuration("SESSIOND_IDLE_TTL", 30*time.Minute)
	if err != nil {
		return err
	}
	absTTL, err := envDuration("SESSIOND_ABSOLUTE_TTL", 12*time.Hour)
	if err != nil {
		return err
	}
	cacheTTL, err := envDuration("SESSIOND_CACHE_TTL", 2*time.Second)
	if err != nil {
		return err
	}
	maxPerUser, err := strconv.Atoi(env("SESSIOND_MAX_PER_USER", "5"))
	if err != nil {
		return fmt.Errorf("SESSIOND_MAX_PER_USER: %w", err)
	}
	policy := store.EvictPolicy(env("SESSIOND_LIMIT_POLICY", string(store.EvictOldest)))
	if policy != store.EvictOldest && policy != store.Reject {
		return fmt.Errorf("SESSIOND_LIMIT_POLICY: unknown policy %q", policy)
	}

	st := store.New(rdb, store.Config{
		IdleTTL:     idleTTL,
		AbsoluteTTL: absTTL,
		MaxPerUser:  maxPerUser,
		Policy:      policy,
		CacheTTL:    cacheTTL,
		Logger:      logger,
	})

	// Revocation listener. If the subscription drops, the store has already
	// flushed its cache (correctness holds via CacheTTL); just resubscribe.
	go func() {
		for ctx.Err() == nil {
			if err := st.Run(ctx); err != nil && ctx.Err() == nil {
				logger.Warn("revocation listener lost, resubscribing", "err", err)
				time.Sleep(time.Second)
			}
		}
	}()

	srv := server.New(st, server.Config{
		APITokens:  splitList(os.Getenv("SESSIOND_API_TOKENS")),
		EnableDemo: devMode && embedded,
		Logger:     logger,
	})

	httpSrv := &http.Server{
		Addr:              env("SESSIOND_ADDR", ":8082"),
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() {
		logger.Info("sessiond listening", "addr", httpSrv.Addr)
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
