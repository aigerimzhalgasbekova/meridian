// Package client is the Go client for the keysmith service: remote signing
// plus local verification against a cached JWKS.
//
// Verification is local by design — verifiers fetch public keys and check
// signatures themselves rather than calling keysmith per token, so token
// validation stays fast and keeps working while keysmith is unreachable. The
// JWKS cache honors Cache-Control max-age and revalidates with ETags; on
// refresh failure it serves stale keys rather than failing closed on reads
// (an unreachable key server must not take down every verifier with it).
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aikazzh/portfolio/keysmith/jose"
)

// Client talks to a keysmith service.
type Client struct {
	baseURL     string
	signerToken string
	httpc       *http.Client
	now         func() time.Time

	mu          sync.RWMutex
	keys        *jose.KeySet
	rawJWKS     []byte
	etag        string
	fetchedAt   time.Time
	maxAge      time.Duration
	staleLogged bool // one warning per outage, not one per verify

	flightMu sync.Mutex
	flight   *flight   // in-progress refresh, if any
	lastKid  time.Time // last unknown-kid-triggered refresh
}

// flight is one in-progress JWKS refresh that concurrent callers share.
type flight struct {
	done chan struct{}
	set  *jose.KeySet
	err  error
}

// unknownKidInterval bounds how often an unrecognized kid may trigger a fetch.
// jose reports ErrUnknownKey after only base64-decoding the token header —
// before any cryptography — so the kid is attacker-chosen and free to vary.
// Without this bound one bearer token per request is one JWKS fetch per
// request, and a verifier under load becomes a load generator against the key
// server it depends on. A real rotation still refreshes on the first unknown
// kid; only the repeats are throttled.
const unknownKidInterval = 10 * time.Second

// Option configures the client.
type Option func(*Client)

// WithHTTPClient overrides the underlying *http.Client.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.httpc = h } }

// WithClock overrides the clock (tests).
func WithClock(now func() time.Time) Option { return func(c *Client) { c.now = now } }

// New builds a Client. signerToken may be empty for verify-only use.
func New(baseURL, signerToken string, opts ...Option) *Client {
	c := &Client{
		baseURL:     strings.TrimRight(baseURL, "/"),
		signerToken: signerToken,
		httpc:       &http.Client{Timeout: 10 * time.Second},
		now:         time.Now,
		maxAge:      5 * time.Minute,
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// SignRequest mirrors the service's sign API.
type SignRequest struct {
	Claims     jose.Claims
	TTLSeconds int64
	Alg        jose.Algorithm
}

// Sign requests a signature from the service.
func (c *Client) Sign(ctx context.Context, req SignRequest) (token string, err error) {
	rawClaims, err := json.Marshal(req.Claims)
	if err != nil {
		return "", err
	}
	body, err := json.Marshal(map[string]any{
		"claims":      json.RawMessage(rawClaims),
		"ttl_seconds": req.TTLSeconds,
		"alg":         string(req.Alg),
	})
	if err != nil {
		return "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/sign", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.signerToken)
	resp, err := c.httpc.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("keysmith client: sign: %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("keysmith client: sign: %s: %s", resp.Status, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	return out.Token, nil
}

// ErrNoKeys means no JWKS has ever been fetched successfully.
var ErrNoKeys = errors.New("keysmith client: no verification keys available")

// Verify checks a token locally against the cached JWKS.
func (c *Client) Verify(ctx context.Context, token string, expect jose.Expect) (jose.Claims, error) {
	set, err := c.keySet(ctx)
	if err != nil {
		return jose.Claims{}, err
	}
	if expect.Now == nil {
		expect.Now = c.now
	}
	claims, err := jose.VerifyClaims(token, set,
		[]jose.Algorithm{jose.AlgEdDSA, jose.AlgES256, jose.AlgRS256}, expect)
	if errors.Is(err, jose.ErrUnknownKey) && c.allowKidRefresh() {
		// Possibly a token signed by a key newer than our cache: refresh
		// once and retry. This is the path that makes rotation seamless
		// even for verifiers that missed the pending-dwell window.
		if set, ferr := c.refreshOnce(ctx); ferr == nil {
			return jose.VerifyClaims(token, set,
				[]jose.Algorithm{jose.AlgEdDSA, jose.AlgES256, jose.AlgRS256}, expect)
		}
	}
	return claims, err
}

// allowKidRefresh reports whether an unknown kid may trigger a fetch now, and
// claims the slot if so.
func (c *Client) allowKidRefresh() bool {
	c.flightMu.Lock()
	defer c.flightMu.Unlock()
	now := c.now()
	if !c.lastKid.IsZero() && now.Sub(c.lastKid) < unknownKidInterval {
		return false
	}
	c.lastKid = now
	return true
}

// refreshOnce collapses concurrent refreshes into a single outbound fetch:
// the first caller does the work, the rest wait on its result. Without it a
// burst of verifies past max-age becomes a burst of JWKS requests.
func (c *Client) refreshOnce(ctx context.Context) (*jose.KeySet, error) {
	c.flightMu.Lock()
	if f := c.flight; f != nil {
		c.flightMu.Unlock()
		select {
		case <-f.done:
			return f.set, f.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f := &flight{done: make(chan struct{})}
	c.flight = f
	c.flightMu.Unlock()

	// The fetch outlives whoever started it: with Verify called on r.Context(),
	// binding it to the leader lets one client disconnecting mid-fetch fail
	// every parked caller's perfectly valid token. Each caller then honours its
	// own deadline instead of inheriting the leader's.
	go func() {
		f.set, f.err = c.forceRefresh(context.WithoutCancel(ctx))
		c.flightMu.Lock()
		c.flight = nil
		c.flightMu.Unlock()
		close(f.done)
	}()
	select {
	case <-f.done:
		return f.set, f.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// keySet returns cached keys, refreshing if stale. Serves stale on refresh
// failure; fails only if no fetch has ever succeeded.
func (c *Client) keySet(ctx context.Context) (*jose.KeySet, error) {
	c.mu.RLock()
	fresh := c.keys != nil && c.now().Sub(c.fetchedAt) < c.maxAge
	set := c.keys
	c.mu.RUnlock()
	if fresh {
		return set, nil
	}
	newSet, err := c.refreshOnce(ctx)
	if err != nil {
		if set != nil {
			c.logStale(err)
			return set, nil // stale beats broken
		}
		return nil, err
	}
	return newSet, nil
}

// logStale warns once per outage that the key set has stopped refreshing.
// Serving stale keys is deliberate (an unreachable key server must not take
// down every verifier), but doing it *silently* is not: dropping a key out of
// the JWKS is the only revocation this system has, so a verifier that cannot
// reach keysmith has silently lost its revocation coverage, and an operator
// watching an outage would otherwise see nothing but successful verifications.
func (c *Client) logStale(cause error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.staleLogged {
		return
	}
	c.staleLogged = true
	slog.Warn("keysmith: serving stale JWKS", "age", c.now().Sub(c.fetchedAt), "err", cause)
}

// KeysAge reports how long ago the cached JWKS was last fetched successfully,
// so services can alert on a verifier drifting past its revocation horizon.
// Zero if no fetch has ever succeeded.
func (c *Client) KeysAge() time.Duration {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.fetchedAt.IsZero() {
		return 0
	}
	return c.now().Sub(c.fetchedAt)
}

func (c *Client) forceRefresh(ctx context.Context) (*jose.KeySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/.well-known/jwks.json", nil)
	if err != nil {
		return nil, err
	}
	c.mu.RLock()
	if c.etag != "" {
		req.Header.Set("If-None-Match", c.etag)
	}
	c.mu.RUnlock()

	resp, err := c.httpc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keysmith client: jwks fetch: %w", err)
	}
	defer resp.Body.Close()

	c.mu.Lock()
	defer c.mu.Unlock()
	switch resp.StatusCode {
	case http.StatusNotModified:
		c.fetchedAt = c.now()
		c.staleLogged = false
		c.maxAge = parseMaxAge(resp.Header.Get("Cache-Control"), c.maxAge)
		if c.keys == nil {
			return nil, ErrNoKeys
		}
		return c.keys, nil
	case http.StatusOK:
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			return nil, err
		}
		set, err := jose.ParseJWKS(raw)
		if err != nil {
			return nil, err
		}
		c.keys = set
		c.rawJWKS = raw
		c.etag = resp.Header.Get("ETag")
		c.fetchedAt = c.now()
		c.staleLogged = false
		c.maxAge = parseMaxAge(resp.Header.Get("Cache-Control"), 5*time.Minute)
		return set, nil
	default:
		return nil, fmt.Errorf("keysmith client: jwks fetch: %s", resp.Status)
	}
}

// RawJWKS returns the cached JWKS document bytes (refreshing if stale),
// for services that re-publish the key set under their own endpoint.
func (c *Client) RawJWKS(ctx context.Context) ([]byte, error) {
	if _, err := c.keySet(ctx); err != nil {
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.rawJWKS == nil {
		return nil, ErrNoKeys
	}
	return c.rawJWKS, nil
}

// maxJWKSMaxAge caps how long this client will cache a key set whatever the
// response asserts. The server computes JWKSMaxAge <= PendingDwell/2 so that
// verifier caches provably refresh before a pending key starts signing; the
// client is the other half of that invariant and must not honour a header
// (or an intermediary rewriting one) that pins it past the dwell.
const maxJWKSMaxAge = 15 * time.Minute

func parseMaxAge(cacheControl string, fallback time.Duration) time.Duration {
	for part := range strings.SplitSeq(cacheControl, ",") {
		part = strings.TrimSpace(part)
		if v, ok := strings.CutPrefix(part, "max-age="); ok {
			// secs >= 0: an explicit max-age=0 means "always revalidate", not
			// "no opinion" — treating a directive as if it were absent and
			// substituting the 5-minute fallback is the one unambiguous bug.
			if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
				return min(time.Duration(secs)*time.Second, maxJWKSMaxAge)
			}
		}
	}
	return fallback
}
