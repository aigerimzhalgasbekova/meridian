// Command bridged runs the bridge SSO federation gateway.
//
// Dev mode (BRIDGE_DEV_MODE=1) needs zero external accounts: it spins up a
// built-in fake OIDC upstream in-process, registers it as a provider, signs
// assertions with an ephemeral local key, and registers a demo app whose
// callback just echoes the assertion. Open http://127.0.0.1:8080 and click
// through.
//
// Production configuration is env-driven:
//
//	BRIDGE_ADDR            listen address (default :8080)
//	BRIDGE_BASE_URL        externally visible base URL (required outside dev)
//	BRIDGE_HMAC_KEY        >= 32 bytes; state-parameter signing key
//	BRIDGE_GOOGLE_CLIENT_ID / BRIDGE_GOOGLE_CLIENT_SECRET
//	BRIDGE_ENTRA_TENANT / BRIDGE_ENTRA_CLIENT_ID / BRIDGE_ENTRA_CLIENT_SECRET
//	BRIDGE_ENTRA_ALLOWED_TENANTS   comma-separated tid allowlist (multi-tenant)
//
// The assertion signer here is the local ephemeral one; a deployment that
// wants centrally managed keys injects a keysmith-backed Signer instead (see
// internal/server.Signer — keysmith/client's Sign already has the right
// shape).
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aikazzh/portfolio/bridge/internal/directory"
	"github.com/aikazzh/portfolio/bridge/internal/fakeidp"
	"github.com/aikazzh/portfolio/bridge/internal/provider"
	"github.com/aikazzh/portfolio/bridge/internal/server"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	addr := envOr("BRIDGE_ADDR", ":8080")
	dev := os.Getenv("BRIDGE_DEV_MODE") == "1"
	baseURL := os.Getenv("BRIDGE_BASE_URL")
	if baseURL == "" {
		if !dev {
			return fmt.Errorf("BRIDGE_BASE_URL is required outside dev mode")
		}
		baseURL = "http://127.0.0.1" + normalizeAddr(addr)
	}

	hmacKey := []byte(os.Getenv("BRIDGE_HMAC_KEY"))
	if len(hmacKey) == 0 && dev {
		hmacKey = make([]byte, 32)
		rand.Read(hmacKey)
	}

	var providers []*provider.Provider
	apps := map[string]server.App{}

	if dev {
		fake := fakeidp.New("bridge-dev", "bridge-dev-secret", fakeidp.User{
			Subject: "dev-user-1", Email: "dev@example.test", Name: "Dev User",
		})
		defer fake.Close()
		p, err := provider.New(provider.Config{
			Name: "dev", DisplayName: "Dev Upstream (built-in)",
			Issuer: fake.URL, ClientID: "bridge-dev", ClientSecret: "bridge-dev-secret",
		})
		if err != nil {
			return err
		}
		providers = append(providers, p)
		log.Printf("dev mode: built-in fake upstream at %s", fake.URL)

		// A second fake upstream asserting the same email under a different
		// subject, to demo the collision/linking story end to end.
		fake2 := fakeidp.New("bridge-dev2", "bridge-dev2-secret", fakeidp.User{
			Subject: "other-user-1", Email: "dev@example.test", Name: "Dev User (elsewhere)",
		})
		defer fake2.Close()
		p2, err := provider.New(provider.Config{
			Name: "dev2", DisplayName: "Second Dev Upstream",
			Issuer: fake2.URL, ClientID: "bridge-dev2", ClientSecret: "bridge-dev2-secret",
		})
		if err != nil {
			return err
		}
		providers = append(providers, p2)

		// Demo relying app: echoes the assertion it receives.
		apps["demo"] = server.App{Name: "Demo App", CallbackURL: baseURL + "/dev/app-callback"}
	}

	if cid := os.Getenv("BRIDGE_GOOGLE_CLIENT_ID"); cid != "" {
		p, err := provider.New(provider.Google(cid, os.Getenv("BRIDGE_GOOGLE_CLIENT_SECRET")))
		if err != nil {
			return err
		}
		providers = append(providers, p)
	}
	if tenant := os.Getenv("BRIDGE_ENTRA_TENANT"); tenant != "" {
		var allowed []string
		if v := os.Getenv("BRIDGE_ENTRA_ALLOWED_TENANTS"); v != "" {
			allowed = strings.Split(v, ",")
		}
		p, err := provider.New(provider.Entra(tenant,
			os.Getenv("BRIDGE_ENTRA_CLIENT_ID"), os.Getenv("BRIDGE_ENTRA_CLIENT_SECRET"), allowed...))
		if err != nil {
			return err
		}
		providers = append(providers, p)
	}
	if len(providers) == 0 {
		return fmt.Errorf("no providers configured (set BRIDGE_DEV_MODE=1 or provider credentials)")
	}

	reg, err := provider.NewRegistry(providers...)
	if err != nil {
		return err
	}
	signer, _, err := server.NewLocalSigner()
	if err != nil {
		return err
	}
	srv, err := server.New(server.Config{
		BaseURL:     baseURL,
		HMACKey:     hmacKey,
		Apps:        apps,
		InsecureDev: dev,
	}, reg, directory.NewMemStore(nil), signer)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.Handle("/", srv)
	if dev {
		mux.HandleFunc("GET /dev/app-callback", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintf(w, "<h1>Demo app</h1><p>Received assertion:</p><pre>%s</pre>",
				html.EscapeString(r.URL.Query().Get("assertion")))
		})
	}

	// Timeouts are not optional on a public listener: without them a handful
	// of idle connections holds sockets open indefinitely (Slowloris).
	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Printf("bridge listening on %s (base %s)", addr, baseURL)
		if err := httpSrv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}

	log.Print("shutting down")
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

func normalizeAddr(addr string) string {
	if strings.HasPrefix(addr, ":") {
		return addr
	}
	if i := strings.LastIndex(addr, ":"); i >= 0 {
		return addr[i:]
	}
	return ":" + addr
}
