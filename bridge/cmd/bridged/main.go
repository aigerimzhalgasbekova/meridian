// Command bridged runs the bridge SSO federation gateway.
//
// Dev mode (BRIDGE_DEV_MODE=1) needs zero external accounts: it spins up a
// built-in fake OIDC upstream in-process, registers it as a provider, signs
// assertions with an ephemeral local key, and registers a demo app whose
// callback just echoes the assertion. `make run-dev` publishes it on :8083
// (the code default would collide with idp); open http://127.0.0.1:8083 and
// click through.
//
// Production configuration is env-driven:
//
//	BRIDGE_ADDR            listen address (default :8080, the in-container
//	                       port; compose and ECS publish it behind :8083)
//	BRIDGE_BASE_URL        externally visible base URL (required outside dev)
//	BRIDGE_HMAC_KEY        >= 32 bytes; state-parameter signing key
//	BRIDGE_GOOGLE_CLIENT_ID / BRIDGE_GOOGLE_CLIENT_SECRET
//	BRIDGE_ENTRA_TENANT / BRIDGE_ENTRA_CLIENT_ID / BRIDGE_ENTRA_CLIENT_SECRET
//	BRIDGE_ENTRA_ALLOWED_TENANTS   comma-separated tid allowlist (multi-tenant)
//	BRIDGE_APPS            relying applications, comma-separated
//	                       id=https://app.example.com/callback pairs. Assertions
//	                       go only to these exact URLs; a malformed entry fails
//	                       startup rather than surfacing as a 400 on ?app= the
//	                       day someone tries to integrate.
//
// The assertion signer here is the local ephemeral one; a deployment that
// wants centrally managed keys injects a keysmith-backed Signer instead (see
// internal/server.Signer — keysmith/client's Sign already has the right
// shape). Either way the verification key is published at
// /.well-known/jwks.json so relying apps can verify assertions without an
// out-of-band key exchange.
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/aikazzh/portfolio/bridge/internal/directory"
	"github.com/aikazzh/portfolio/bridge/internal/fakeidp"
	"github.com/aikazzh/portfolio/bridge/internal/provider"
	"github.com/aikazzh/portfolio/bridge/internal/server"
	"github.com/aikazzh/portfolio/keysmith/jose"
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

	if err := parseApps(os.Getenv("BRIDGE_APPS"), apps); err != nil {
		return err
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
	signer, verKey, err := server.NewLocalSigner()
	if err != nil {
		return err
	}
	jwks, err := jose.PublicJWK(verKey)
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
	// Assertions are worthless to a relying app that cannot verify them, and
	// the signing key is generated per process — publish the public half.
	mux.HandleFunc("GET /.well-known/jwks.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		json.NewEncoder(w).Encode(jose.JWKS{Keys: []jose.JWK{jwks}})
	})
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

// parseApps reads BRIDGE_APPS ("id=https://host/cb,id2=https://…") into apps.
// Validation is at startup on purpose: an unregistered app id is a silent 400
// on /login/{p}?app=X at request time, which is a miserable thing to discover
// during someone else's integration.
func parseApps(spec string, apps map[string]server.App) error {
	if spec == "" {
		return nil
	}
	for entry := range strings.SplitSeq(spec, ",") {
		id, raw, ok := strings.Cut(strings.TrimSpace(entry), "=")
		if !ok || id == "" {
			return fmt.Errorf("BRIDGE_APPS: %q is not id=callback-url", entry)
		}
		u, err := url.Parse(raw)
		if err != nil {
			return fmt.Errorf("BRIDGE_APPS: app %q: %w", id, err)
		}
		// An assertion is a bearer credential; https and an absolute URL are
		// the floor. Dev mode's demo app is registered directly, not here.
		if u.Scheme != "https" || u.Host == "" {
			return fmt.Errorf("BRIDGE_APPS: app %q: callback %q must be an absolute https URL", id, raw)
		}
		if _, dup := apps[id]; dup {
			return fmt.Errorf("BRIDGE_APPS: duplicate app id %q", id)
		}
		apps[id] = server.App{Name: id, CallbackURL: u.String()}
	}
	return nil
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
