// Package provider is bridge's registry of upstream identity providers and
// the OIDC Relying-Party plumbing for talking to them: discovery metadata
// (RFC 8414 / OIDC Discovery) with ETag-revalidated caching, JWKS caching
// with bounded stale tolerance and kid-miss refresh, the authorization-code
// token exchange, and full ID-token verification.
//
// Every network touch of an upstream (discovery, JWKS, token exchange) runs
// through that provider's circuit breaker, so a dead upstream degrades to an
// immediate error instead of a hung connection — see internal/health.
//
// # Verification stance
//
// ID tokens are verified with keysmith/jose, which is allowlist-only by
// construction: no "none", no HMAC, mandatory kid, the key set (never the
// token) decides the algorithm. On top of that this package enforces the
// RP-side checks OIDC Core §3.1.3.7 demands: exact issuer match, audience
// contains our client_id, azp naming us whenever it is present or aud is
// multi-valued (rules 4-5), expiry, and nonce binding to the login flow. A
// token with no sub is refused outright — (provider, subject) is the whole
// identity model, so an absent subject is not a degraded login, it is a
// cross-account merge waiting to happen.
// The algorithm allowlist for upstream tokens is RS256 and ES256 — what
// Google and Entra ID actually sign with.
//
// # The Entra tenanted-issuer sharp edge
//
// Microsoft Entra ID's multi-tenant discovery document (issuer
// https://login.microsoftonline.com/common/v2.0) declares its issuer as the
// literal template "https://login.microsoftonline.com/{tenantid}/v2.0", and
// real tokens carry the tenant GUID substituted in. A naive RP that compares
// token iss against the metadata issuer string rejects every valid token; a
// sloppier one that skips the issuer check accepts tokens from *any* Entra
// tenant — meaning any Microsoft account in the world can log in to your app.
// This package handles it explicitly: when the configured issuer contains
// "{tenantid}", the expected issuer for each token is the template with the
// token's tid claim substituted, and tid itself may be restricted by
// Config.AllowedTenants. See docs/adr and THREAT_MODEL.md.
package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aikazzh/portfolio/bridge/internal/health"
	"github.com/aikazzh/portfolio/keysmith/jose"
)

// TenantPlaceholder is the literal placeholder Entra ID uses in its
// multi-tenant discovery document's issuer value.
const TenantPlaceholder = "{tenantid}"

// Config describes one upstream provider.
type Config struct {
	// Name keys the provider in URLs (/login/{name}) and in claims (idp).
	Name string
	// DisplayName is shown on the provider picker.
	DisplayName string
	// Issuer is the expected iss of ID tokens. It may contain
	// TenantPlaceholder for Entra-style multi-tenant issuers.
	Issuer string
	// DiscoveryURL overrides the default <Issuer>/.well-known/openid-configuration.
	// Required when Issuer contains TenantPlaceholder (the template is not a
	// fetchable URL).
	DiscoveryURL string
	ClientID     string
	ClientSecret string
	// Scopes defaults to openid, email, profile.
	Scopes []string
	// AllowedTenants restricts which tid values are accepted for a templated
	// (multi-tenant) issuer. Required non-empty for such issuers — New
	// rejects an empty list rather than admitting any Microsoft tenant on
	// earth.
	AllowedTenants []string
}

// Google returns the preset for Google Sign-In.
func Google(clientID, clientSecret string) Config {
	return Config{
		Name:         "google",
		DisplayName:  "Google",
		Issuer:       "https://accounts.google.com",
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
}

// Entra returns the preset for Microsoft Entra ID. tenant is a tenant GUID,
// a verified domain, or one of the pseudo-tenants "common" / "organizations"
// / "consumers". For pseudo-tenants the issuer is the {tenantid} template and
// per-token tenant validation applies (see package doc); allowedTenants is
// required for these pseudo-tenants — New rejects the config otherwise.
func Entra(tenant, clientID, clientSecret string, allowedTenants ...string) Config {
	cfg := Config{
		Name:         "entra",
		DisplayName:  "Microsoft",
		Issuer:       "https://login.microsoftonline.com/" + tenant + "/v2.0",
		DiscoveryURL: "https://login.microsoftonline.com/" + tenant + "/v2.0/.well-known/openid-configuration",
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}
	switch tenant {
	case "common", "organizations", "consumers":
		cfg.Issuer = "https://login.microsoftonline.com/" + TenantPlaceholder + "/v2.0"
		cfg.AllowedTenants = allowedTenants
	}
	return cfg
}

// Metadata is the subset of the discovery document bridge uses.
type Metadata struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// Provider errors, comparable with errors.Is.
var (
	ErrIssuerMismatch  = errors.New("provider: ID token issuer does not match expected issuer")
	ErrNonceMismatch   = errors.New("provider: ID token nonce does not match the login flow")
	ErrTenantRejected  = errors.New("provider: token tenant is not in the allowed tenant list")
	ErrKeysUnavailable = errors.New("provider: no JWKS available and refresh failed")
	ErrMissingSubject  = errors.New("provider: ID token has no sub claim")
	ErrAzpMismatch     = errors.New("provider: ID token azp does not name this client")
)

// upstreamAlgs is the signature-algorithm allowlist for upstream ID tokens.
var upstreamAlgs = []jose.Algorithm{jose.AlgRS256, jose.AlgES256}

// jwksStaleLimit bounds how long a cached JWKS may be served past its
// freshness window when the upstream is unreachable. Within the bound,
// verification keeps working through an upstream outage (public keys do not
// go bad because the server hosting them is down); past it we fail closed,
// because a key revoked after compromise must eventually stop verifying.
const jwksStaleLimit = 24 * time.Hour

// metaStaleLimit bounds how long cached discovery metadata may be served past
// its freshness window when the discovery endpoint is unreachable. Mirrors
// jwksStaleLimit: endpoints move rarely, so a login should survive a brief
// outage — but unbounded, a token_endpoint hostname the upstream has since
// decommissioned or re-registered would keep receiving the client_secret and
// live authorization codes forever. Past the bound we fail closed.
const metaStaleLimit = 24 * time.Hour

const (
	defaultMaxAge = 5 * time.Minute
	maxBody       = 1 << 20
)

// Provider is one configured upstream: config + cached discovery + cached
// JWKS + circuit breaker. Safe for concurrent use.
type Provider struct {
	cfg     Config
	hc      *http.Client
	breaker *health.Breaker
	now     func() time.Time

	mu sync.Mutex
	// discovery cache
	meta        *Metadata
	metaETag    string
	metaFetched time.Time
	metaMaxAge  time.Duration
	// JWKS cache
	keys        *jose.KeySet
	jwksETag    string
	jwksFetched time.Time
	jwksMaxAge  time.Duration
}

// Option configures a Provider.
type Option func(*Provider)

// WithHTTPClient overrides the HTTP client (tests point it at a fake upstream).
func WithHTTPClient(hc *http.Client) Option { return func(p *Provider) { p.hc = hc } }

// WithClock overrides the clock (tests).
func WithClock(now func() time.Time) Option { return func(p *Provider) { p.now = now } }

// WithBreaker overrides the circuit breaker (tests tune threshold/cooldown).
func WithBreaker(b *health.Breaker) Option { return func(p *Provider) { p.breaker = b } }

// New builds a Provider from cfg.
func New(cfg Config, opts ...Option) (*Provider, error) {
	if cfg.Name == "" || cfg.Issuer == "" || cfg.ClientID == "" {
		return nil, errors.New("provider: Name, Issuer and ClientID are required")
	}
	if strings.Contains(cfg.Issuer, TenantPlaceholder) && len(cfg.AllowedTenants) == 0 {
		return nil, errors.New("provider: multi-tenant Entra endpoint requires a non-empty AllowedTenants list")
	}
	if cfg.DiscoveryURL == "" {
		if strings.Contains(cfg.Issuer, TenantPlaceholder) {
			return nil, errors.New("provider: templated issuer requires an explicit DiscoveryURL")
		}
		cfg.DiscoveryURL = strings.TrimRight(cfg.Issuer, "/") + "/.well-known/openid-configuration"
	}
	if len(cfg.Scopes) == 0 {
		cfg.Scopes = []string{"openid", "email", "profile"}
	}
	p := &Provider{
		cfg: cfg,
		hc:  &http.Client{Timeout: 10 * time.Second},
		now: time.Now,
	}
	for _, o := range opts {
		o(p)
	}
	if p.breaker == nil {
		p.breaker = health.New(5, 30*time.Second, p.now)
	}
	return p, nil
}

// Config returns the provider configuration.
func (p *Provider) Config() Config { return p.cfg }

// Breaker exposes the circuit breaker for health reporting.
func (p *Provider) Breaker() *health.Breaker { return p.breaker }

// Healthy reports whether the breaker currently admits calls.
func (p *Provider) Healthy() bool { return p.breaker.State() != health.Open }

// Metadata returns the discovery document, from cache when fresh. On refresh
// failure a stale document is served up to metaStaleLimit (endpoints move
// rarely; a login that can proceed on hours-old endpoint URLs should), then we
// fail closed rather than POST credentials to an endpoint that may have moved.
func (p *Provider) Metadata(ctx context.Context) (*Metadata, error) {
	p.mu.Lock()
	fresh := p.meta != nil && p.now().Sub(p.metaFetched) < p.maxAgeOr(p.metaMaxAge)
	meta, fetched := p.meta, p.metaFetched
	p.mu.Unlock()
	if fresh {
		return meta, nil
	}
	if err := p.breaker.Do(func() error { return p.refreshMetadata(ctx) }); err != nil {
		if meta != nil && p.now().Sub(fetched) < metaStaleLimit {
			return meta, nil // bounded stale tolerance
		}
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.meta, nil
}

func (p *Provider) maxAgeOr(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultMaxAge
	}
	return d
}

func (p *Provider) refreshMetadata(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.DiscoveryURL, nil)
	if err != nil {
		return err
	}
	p.mu.Lock()
	if p.metaETag != "" {
		req.Header.Set("If-None-Match", p.metaETag)
	}
	p.mu.Unlock()
	resp, err := p.hc.Do(req)
	if err != nil {
		return fmt.Errorf("provider %s: discovery: %w", p.cfg.Name, err)
	}
	defer resp.Body.Close()

	p.mu.Lock()
	defer p.mu.Unlock()
	switch resp.StatusCode {
	case http.StatusNotModified:
		if p.meta == nil {
			return fmt.Errorf("provider %s: discovery 304 without a cached document", p.cfg.Name)
		}
		p.metaFetched = p.now()
		p.metaMaxAge = parseMaxAge(resp.Header.Get("Cache-Control"))
		return nil
	case http.StatusOK:
		var meta Metadata
		if err := decodeJSON(resp.Body, &meta); err != nil {
			return fmt.Errorf("provider %s: discovery: %w", p.cfg.Name, err)
		}
		// RFC 8414 §3.3: the issuer in the document must match what we asked
		// for, or we may be talking to an impostor (or a misconfiguration).
		// Entra's multi-tenant document declares the {tenantid} template,
		// which is exactly what our configured issuer holds in that mode.
		if meta.Issuer != p.cfg.Issuer {
			return fmt.Errorf("provider %s: discovery issuer %q does not match configured %q",
				p.cfg.Name, meta.Issuer, p.cfg.Issuer)
		}
		if meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" || meta.JWKSURI == "" {
			return fmt.Errorf("provider %s: discovery document missing required endpoints", p.cfg.Name)
		}
		p.meta = &meta
		p.metaETag = resp.Header.Get("ETag")
		p.metaFetched = p.now()
		p.metaMaxAge = parseMaxAge(resp.Header.Get("Cache-Control"))
		return nil
	default:
		return fmt.Errorf("provider %s: discovery: %s", p.cfg.Name, resp.Status)
	}
}

// keySet returns the cached JWKS, refreshing when stale. On refresh failure a
// stale set is served up to jwksStaleLimit, then verification fails closed.
func (p *Provider) keySet(ctx context.Context) (*jose.KeySet, error) {
	p.mu.Lock()
	fresh := p.keys != nil && p.now().Sub(p.jwksFetched) < p.maxAgeOr(p.jwksMaxAge)
	set, fetched := p.keys, p.jwksFetched
	p.mu.Unlock()
	if fresh {
		return set, nil
	}
	if err := p.refreshKeys(ctx); err != nil {
		if set != nil && p.now().Sub(fetched) < jwksStaleLimit {
			return set, nil // bounded stale tolerance
		}
		return nil, fmt.Errorf("%w: %v", ErrKeysUnavailable, err)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.keys, nil
}

func (p *Provider) refreshKeys(ctx context.Context) error {
	meta, err := p.Metadata(ctx)
	if err != nil {
		return err
	}
	return p.breaker.Do(func() error {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, meta.JWKSURI, nil)
		if err != nil {
			return err
		}
		p.mu.Lock()
		if p.jwksETag != "" {
			req.Header.Set("If-None-Match", p.jwksETag)
		}
		p.mu.Unlock()
		resp, err := p.hc.Do(req)
		if err != nil {
			return fmt.Errorf("provider %s: jwks: %w", p.cfg.Name, err)
		}
		defer resp.Body.Close()

		p.mu.Lock()
		defer p.mu.Unlock()
		switch resp.StatusCode {
		case http.StatusNotModified:
			if p.keys == nil {
				return fmt.Errorf("provider %s: jwks 304 without cached keys", p.cfg.Name)
			}
			p.jwksFetched = p.now()
			p.jwksMaxAge = parseMaxAge(resp.Header.Get("Cache-Control"))
			return nil
		case http.StatusOK:
			raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
			if err != nil {
				return err
			}
			set, err := jose.ParseJWKS(raw)
			if err != nil {
				return fmt.Errorf("provider %s: %w", p.cfg.Name, err)
			}
			p.keys = set
			p.jwksETag = resp.Header.Get("ETag")
			p.jwksFetched = p.now()
			p.jwksMaxAge = parseMaxAge(resp.Header.Get("Cache-Control"))
			return nil
		default:
			return fmt.Errorf("provider %s: jwks: %s", p.cfg.Name, resp.Status)
		}
	})
}

// AuthorizeURL builds the upstream authorization redirect for one login flow.
func (p *Provider) AuthorizeURL(ctx context.Context, state, nonce, codeChallenge, redirectURI string) (string, error) {
	meta, err := p.Metadata(ctx)
	if err != nil {
		return "", err
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(p.cfg.Scopes, " ")},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(meta.AuthorizationEndpoint, "?") {
		sep = "&"
	}
	return meta.AuthorizationEndpoint + sep + q.Encode(), nil
}

// Exchange redeems an authorization code at the upstream token endpoint and
// returns the raw ID token. It runs under the circuit breaker: a dead token
// endpoint fails fast after the breaker opens.
func (p *Provider) Exchange(ctx context.Context, code, codeVerifier, redirectURI string) (string, error) {
	meta, err := p.Metadata(ctx)
	if err != nil {
		return "", err
	}
	var idToken string
	err = p.breaker.Do(func() error {
		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {code},
			"redirect_uri":  {redirectURI},
			"client_id":     {p.cfg.ClientID},
			"client_secret": {p.cfg.ClientSecret},
			"code_verifier": {codeVerifier},
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.TokenEndpoint,
			strings.NewReader(form.Encode()))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := p.hc.Do(req)
		if err != nil {
			return fmt.Errorf("provider %s: token exchange: %w", p.cfg.Name, err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		if err != nil {
			return err
		}
		if resp.StatusCode != http.StatusOK {
			// The body goes into an error that gets logged. A real IdP sends a
			// few bytes of JSON; a proxy or captive portal in front of a dead
			// token endpoint sends an HTML page, and maxBody is 1 MiB — so keep
			// only enough to diagnose, per failed callback.
			body := strings.TrimSpace(string(raw))
			if len(body) > 512 {
				body = strings.ToValidUTF8(body[:512], "") + "…"
			}
			return fmt.Errorf("provider %s: token exchange: %s: %s",
				p.cfg.Name, resp.Status, body)
		}
		var out struct {
			IDToken string `json:"id_token"`
		}
		if err := decodeJSON(strings.NewReader(string(raw)), &out); err != nil {
			return fmt.Errorf("provider %s: token response: %w", p.cfg.Name, err)
		}
		if out.IDToken == "" {
			return fmt.Errorf("provider %s: token response has no id_token", p.cfg.Name)
		}
		idToken = out.IDToken
		return nil
	})
	return idToken, err
}

// VerifyIDToken fully validates an upstream ID token: signature against the
// provider's JWKS (RS256/ES256 only), exp/iat, aud contains our client_id,
// nonce binding, and issuer — including the Entra tenanted-issuer rule.
//
// On an unknown kid the JWKS is force-refreshed once and verification
// retried: upstreams rotate keys without notice, and a token signed by a key
// newer than our cache is routine, not an attack.
func (p *Provider) VerifyIDToken(ctx context.Context, idToken, nonce string) (jose.Claims, error) {
	set, err := p.keySet(ctx)
	if err != nil {
		return jose.Claims{}, err
	}
	expect := jose.Expect{Audience: p.cfg.ClientID, Now: p.now, Leeway: time.Minute}
	claims, err := jose.VerifyClaims(idToken, set, upstreamAlgs, expect)
	if errors.Is(err, jose.ErrUnknownKey) {
		if rerr := p.refreshKeys(ctx); rerr == nil {
			p.mu.Lock()
			set = p.keys
			p.mu.Unlock()
			claims, err = jose.VerifyClaims(idToken, set, upstreamAlgs, expect)
		}
	}
	if err != nil {
		return jose.Claims{}, err
	}
	if err := p.checkIssuer(claims); err != nil {
		return jose.Claims{}, err
	}
	// OIDC Core §3.1.3.7 rules 4-5: when aud carries more than one value, azp
	// must be present and name us; when azp is present at all it must name us,
	// whatever aud's arity. jose.Expect{Audience} is membership only, so
	// without this a token minted for another client that merely *lists* us in
	// aud would pass.
	if azp, present := claims.Extra["azp"]; present || len(claims.Audience) > 1 {
		if s, _ := azp.(string); s != p.cfg.ClientID {
			return jose.Claims{}, fmt.Errorf("%w: azp %v", ErrAzpMismatch, azp)
		}
	}
	// The whole identity model keys on (provider, subject). OIDC Core §2
	// guarantees sub exists and is stable, but a non-conformant or
	// misconfigured upstream that omits it would collapse every one of its
	// users onto the single identity holding the empty subject.
	if claims.Subject == "" {
		return jose.Claims{}, ErrMissingSubject
	}
	got, _ := claims.Extra["nonce"].(string)
	if nonce == "" || got != nonce {
		return jose.Claims{}, ErrNonceMismatch
	}
	return claims, nil
}

// checkIssuer enforces exact issuer match, resolving the Entra {tenantid}
// template against the token's tid claim first.
func (p *Provider) checkIssuer(claims jose.Claims) error {
	expected := p.cfg.Issuer
	if strings.Contains(expected, TenantPlaceholder) {
		tid, _ := claims.Extra["tid"].(string)
		if tid == "" {
			return fmt.Errorf("%w: templated issuer requires a tid claim", ErrIssuerMismatch)
		}
		if len(p.cfg.AllowedTenants) > 0 {
			allowed := false
			for _, t := range p.cfg.AllowedTenants {
				if t == tid {
					allowed = true
					break
				}
			}
			if !allowed {
				return fmt.Errorf("%w: tid %q", ErrTenantRejected, tid)
			}
		}
		expected = strings.ReplaceAll(expected, TenantPlaceholder, tid)
	}
	if claims.Issuer != expected {
		return fmt.Errorf("%w: got %q, want %q", ErrIssuerMismatch, claims.Issuer, expected)
	}
	return nil
}

// Registry is a fixed set of providers keyed by name.
type Registry struct {
	byName map[string]*Provider
	order  []string
}

// NewRegistry builds a Registry, rejecting duplicate names.
func NewRegistry(providers ...*Provider) (*Registry, error) {
	r := &Registry{byName: make(map[string]*Provider, len(providers))}
	for _, p := range providers {
		name := p.cfg.Name
		if _, dup := r.byName[name]; dup {
			return nil, fmt.Errorf("provider: duplicate name %q", name)
		}
		r.byName[name] = p
		r.order = append(r.order, name)
	}
	return r, nil
}

// Get returns the named provider, or nil.
func (r *Registry) Get(name string) *Provider { return r.byName[name] }

// All returns providers in registration order.
func (r *Registry) All() []*Provider {
	out := make([]*Provider, 0, len(r.order))
	for _, name := range r.order {
		out = append(out, r.byName[name])
	}
	return out
}

func decodeJSON(r io.Reader, v any) error {
	return json.NewDecoder(io.LimitReader(r, maxBody)).Decode(v)
}

func parseMaxAge(cacheControl string) time.Duration {
	for part := range strings.SplitSeq(cacheControl, ",") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "max-age="); ok {
			if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
				return time.Duration(secs) * time.Second
			}
		}
	}
	return 0
}
