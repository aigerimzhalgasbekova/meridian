package provider

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aikazzh/portfolio/bridge/internal/fakeidp"
	"github.com/aikazzh/portfolio/bridge/internal/health"
	"github.com/aikazzh/portfolio/bridge/internal/relay"
	"github.com/aikazzh/portfolio/keysmith/jose"
)

const (
	clientID     = "bridge-client"
	clientSecret = "bridge-secret"
	redirectURI  = "http://rp.example/callback/fake"
)

var alice = fakeidp.User{Subject: "sub-alice", Email: "alice@example.com", Name: "Alice"}

func newProvider(t *testing.T, s *fakeidp.Server, opts ...Option) *Provider {
	t.Helper()
	p, err := New(Config{
		Name: "fake", Issuer: s.URL, ClientID: clientID, ClientSecret: clientSecret,
	}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// authenticate drives authorize → code → exchange against the fake upstream
// and returns the raw ID token, using a fresh flow's nonce/verifier.
func authenticate(t *testing.T, s *fakeidp.Server, p *Provider) (idToken, nonce string) {
	t.Helper()
	ctx := context.Background()
	nonce, verifier := "test-nonce-"+t.Name(), strings.Repeat("v", 43)
	authURL, err := p.AuthorizeURL(ctx, "test-state", nonce, relay.Challenge(verifier), redirectURI)
	if err != nil {
		t.Fatalf("AuthorizeURL: %v", err)
	}
	hc := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := hc.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: status %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect %q", loc)
	}
	token, err := p.Exchange(ctx, code, verifier, redirectURI)
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	return token, nonce
}

func TestVerifyIDToken(t *testing.T) {
	s := fakeidp.New(clientID, clientSecret, alice)
	defer s.Close()
	ctx := context.Background()

	t.Run("happy path", func(t *testing.T) {
		p := newProvider(t, s)
		token, nonce := authenticate(t, s, p)
		claims, err := p.VerifyIDToken(ctx, token, nonce)
		if err != nil {
			t.Fatal(err)
		}
		if claims.Subject != alice.Subject || claims.Extra["email"] != alice.Email {
			t.Fatalf("claims: %+v", claims)
		}
	})

	t.Run("tampered token rejected", func(t *testing.T) {
		p := newProvider(t, s)
		token, nonce := authenticate(t, s, p)
		parts := strings.Split(token, ".")
		// Flip the payload: claims change, signature doesn't.
		tampered := parts[0] + "." + strings.Map(func(r rune) rune {
			if r == 'a' {
				return 'b'
			}
			return r
		}, parts[1]) + "." + parts[2]
		if _, err := p.VerifyIDToken(ctx, tampered, nonce); err == nil {
			t.Fatal("tampered token verified")
		}
	})

	t.Run("wrong issuer rejected", func(t *testing.T) {
		p := newProvider(t, s)
		s.SetTokenIssuer("https://evil.example")
		defer s.SetTokenIssuer("")
		token, nonce := authenticate(t, s, p)
		if _, err := p.VerifyIDToken(ctx, token, nonce); !errors.Is(err, ErrIssuerMismatch) {
			t.Fatalf("got %v, want ErrIssuerMismatch", err)
		}
	})

	t.Run("nonce mismatch rejected", func(t *testing.T) {
		p := newProvider(t, s)
		s.SetNonceOverride("stolen-nonce")
		defer s.SetNonceOverride("")
		token, _ := authenticate(t, s, p)
		if _, err := p.VerifyIDToken(ctx, token, "the-real-nonce"); !errors.Is(err, ErrNonceMismatch) {
			t.Fatalf("got %v, want ErrNonceMismatch", err)
		}
	})

	t.Run("token signed by unpublished key rejected", func(t *testing.T) {
		p := newProvider(t, s)
		s.SetUnpublishedKey(true)
		defer s.SetUnpublishedKey(false)
		token, nonce := authenticate(t, s, p)
		if _, err := p.VerifyIDToken(ctx, token, nonce); !errors.Is(err, jose.ErrUnknownKey) {
			t.Fatalf("got %v, want ErrUnknownKey", err)
		}
	})

	t.Run("upstream key rotation mid-session verifies via kid-miss refresh", func(t *testing.T) {
		p := newProvider(t, s)
		token, nonce := authenticate(t, s, p)
		if _, err := p.VerifyIDToken(ctx, token, nonce); err != nil {
			t.Fatalf("pre-rotation verify: %v", err)
		}
		s.RotateKeys() // JWKS now serves only the new key; our cache holds the old
		token2, nonce2 := authenticate(t, s, p)
		claims, err := p.VerifyIDToken(ctx, token2, nonce2)
		if err != nil {
			t.Fatalf("post-rotation verify (kid-miss refresh): %v", err)
		}
		if claims.Subject != alice.Subject {
			t.Fatalf("claims: %+v", claims)
		}
	})
}

func TestEntraTenantedIssuer(t *testing.T) {
	s := fakeidp.New(clientID, clientSecret, alice)
	defer s.Close()
	ctx := context.Background()

	// Multi-tenant Entra shape: discovery declares the literal {tenantid}
	// template; tokens carry the concrete tenant in iss and tid.
	template := s.URL + "/" + TenantPlaceholder + "/v2.0"
	s.SetDiscoveryIssuer(template)
	defer s.SetDiscoveryIssuer("")

	newEntra := func(t *testing.T, allowed ...string) *Provider {
		p, err := New(Config{
			Name: "fake", Issuer: template,
			DiscoveryURL:   s.URL + "/.well-known/openid-configuration",
			ClientID:       clientID,
			ClientSecret:   clientSecret,
			AllowedTenants: allowed,
		})
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	setTenant := func(tid string) {
		s.SetTokenIssuer(s.URL + "/" + tid + "/v2.0")
		s.SetExtraClaims(map[string]any{"tid": tid})
	}
	defer s.SetTokenIssuer("")
	defer s.SetExtraClaims(nil)

	t.Run("iss with tid substituted verifies", func(t *testing.T) {
		setTenant("tenant-a")
		p := newEntra(t, "tenant-a")
		token, nonce := authenticate(t, s, p)
		claims, err := p.VerifyIDToken(ctx, token, nonce)
		if err != nil {
			t.Fatal(err)
		}
		if claims.Extra["tid"] != "tenant-a" {
			t.Fatalf("claims: %+v", claims)
		}
	})

	t.Run("iss/tid mismatch rejected", func(t *testing.T) {
		s.SetTokenIssuer(s.URL + "/tenant-a/v2.0")
		s.SetExtraClaims(map[string]any{"tid": "tenant-b"}) // lies about its tenant
		p := newEntra(t, "tenant-a", "tenant-b")
		token, nonce := authenticate(t, s, p)
		if _, err := p.VerifyIDToken(ctx, token, nonce); !errors.Is(err, ErrIssuerMismatch) {
			t.Fatalf("got %v, want ErrIssuerMismatch", err)
		}
	})

	t.Run("missing tid rejected", func(t *testing.T) {
		s.SetTokenIssuer(s.URL + "/tenant-a/v2.0")
		s.SetExtraClaims(nil)
		p := newEntra(t, "tenant-a")
		token, nonce := authenticate(t, s, p)
		if _, err := p.VerifyIDToken(ctx, token, nonce); !errors.Is(err, ErrIssuerMismatch) {
			t.Fatalf("got %v, want ErrIssuerMismatch", err)
		}
	})

	t.Run("tenant outside allowlist rejected", func(t *testing.T) {
		setTenant("tenant-evil")
		p := newEntra(t, "tenant-a", "tenant-b")
		token, nonce := authenticate(t, s, p)
		if _, err := p.VerifyIDToken(ctx, token, nonce); !errors.Is(err, ErrTenantRejected) {
			t.Fatalf("got %v, want ErrTenantRejected", err)
		}
	})
}

func TestBreakerOpensOnUpstreamFailure(t *testing.T) {
	s := fakeidp.New(clientID, clientSecret, alice)
	defer s.Close()
	ctx := context.Background()

	clock := time.Now()
	now := func() time.Time { return clock }
	b := health.New(3, time.Minute, now)
	p := newProvider(t, s, WithClock(now), WithBreaker(b))

	s.SetFailing(true)
	for i := 0; i < 3; i++ {
		if _, err := p.Metadata(ctx); err == nil {
			t.Fatalf("call %d: expected failure", i)
		}
	}
	if b.State() != health.Open {
		t.Fatalf("breaker state = %s, want open", b.State())
	}
	if _, err := p.Metadata(ctx); !errors.Is(err, health.ErrOpen) {
		t.Fatalf("open breaker must fail fast, got %v", err)
	}

	// Half-open probe after cooldown recovers when the upstream does.
	s.SetFailing(false)
	clock = clock.Add(time.Minute)
	if _, err := p.Metadata(ctx); err != nil {
		t.Fatalf("recovery probe: %v", err)
	}
	if b.State() != health.Closed {
		t.Fatalf("breaker state = %s, want closed", b.State())
	}
}

func TestJWKSStaleTolerance(t *testing.T) {
	s := fakeidp.New(clientID, clientSecret, alice)
	defer s.Close()
	ctx := context.Background()

	clock := time.Now()
	now := func() time.Time { return clock }
	p := newProvider(t, s, WithClock(now),
		WithBreaker(health.New(1000, time.Minute, now))) // keep breaker out of this test

	token, nonce := authenticate(t, s, p)
	if _, err := p.VerifyIDToken(ctx, token, nonce); err != nil {
		t.Fatalf("prime the caches: %v", err)
	}

	t.Run("verification survives upstream outage on stale JWKS", func(t *testing.T) {
		s.SetFailing(false)
		token, nonce := authenticate(t, s, p)
		s.SetFailing(true)
		clock = clock.Add(time.Hour) // cache stale, upstream down, within 24h bound
		if _, err := p.VerifyIDToken(ctx, token, nonce); err != nil {
			t.Fatalf("stale JWKS should still verify within the bound: %v", err)
		}
	})

	t.Run("fails closed past the staleness bound", func(t *testing.T) {
		s.SetFailing(false)
		token, nonce := authenticate(t, s, p)
		s.SetFailing(true)
		clock = clock.Add(25 * time.Hour)
		if _, err := p.VerifyIDToken(ctx, token, nonce); !errors.Is(err, ErrKeysUnavailable) {
			t.Fatalf("got %v, want ErrKeysUnavailable", err)
		}
	})
}

func TestDiscoveryValidation(t *testing.T) {
	s := fakeidp.New(clientID, clientSecret, alice)
	defer s.Close()

	t.Run("issuer mismatch in discovery rejected", func(t *testing.T) {
		s.SetDiscoveryIssuer("https://impostor.example")
		defer s.SetDiscoveryIssuer("")
		p := newProvider(t, s)
		if _, err := p.Metadata(context.Background()); err == nil {
			t.Fatal("mismatched discovery issuer accepted")
		}
	})

	t.Run("templated issuer requires explicit discovery URL", func(t *testing.T) {
		_, err := New(Config{Name: "x", Issuer: "https://x/" + TenantPlaceholder, ClientID: "c"})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("templated issuer with empty AllowedTenants rejected", func(t *testing.T) {
		_, err := New(Config{
			Name: "x", Issuer: "https://x/" + TenantPlaceholder, ClientID: "c",
			DiscoveryURL: "https://x/.well-known/openid-configuration",
		})
		if err == nil {
			t.Fatal("multi-tenant Entra config with empty AllowedTenants must be rejected")
		}
	})
}

func TestPresets(t *testing.T) {
	g := Google("cid", "sec")
	if g.Issuer != "https://accounts.google.com" || g.Name != "google" {
		t.Fatalf("google preset: %+v", g)
	}
	e := Entra("common", "cid", "sec", "tenant-1")
	if !strings.Contains(e.Issuer, TenantPlaceholder) {
		t.Fatalf("multi-tenant entra preset must use the issuer template: %+v", e)
	}
	if e.DiscoveryURL != "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration" {
		t.Fatalf("entra discovery URL: %q", e.DiscoveryURL)
	}
	if len(e.AllowedTenants) != 1 {
		t.Fatalf("allowed tenants: %+v", e.AllowedTenants)
	}
	single := Entra("11111111-2222-3333-4444-555555555555", "cid", "sec")
	if strings.Contains(single.Issuer, TenantPlaceholder) {
		t.Fatalf("single-tenant entra must pin the issuer: %+v", single)
	}
}
