// Package relay manages the per-login state of bridge's RP-side
// authorization-code flow: the state parameter, the nonce, and the PKCE
// verifier.
//
// # Design
//
// The state parameter is an HMAC-SHA256-signed token carrying a random flow
// ID, the provider name, and an expiry. The signature makes state unforgeable
// (an attacker cannot mint a state that our callback accepts), the expiry
// bounds the window, and the flow ID points at a server-side flow record.
//
// The nonce, the PKCE code verifier, and where the user goes afterwards live
// only in that server-side record — never in the state parameter itself. The
// state travels through the upstream's URL, logs, and Referer headers; the
// code verifier especially must not (it is the proof of possession the code
// exchange depends on).
//
// One-time use is enforced by consumption: verifying a state deletes its flow
// record atomically, so a replayed callback — attacker resubmitting a
// captured URL, or a user double-clicking — finds nothing and is rejected.
// The signature check alone cannot provide replay protection; server-side
// state can, which is why both exist. See docs/adr/0003.
//
// One-time use is not the same as browser binding, and neither implies the
// other: a *first* presentation of a genuine, unexpired, unused state is
// accepted by every check above no matter who presents it. Flow.Binding
// closes that: it is a secret the browser holds in a cookie and must present
// alongside the state at Consume, so a callback URL that leaks (or is
// deliberately delivered to a victim) is useless to anyone else.
//
// Flows expire after TTL (10 minutes: enough for a slow login at the
// upstream, short enough that abandoned flows don't pile up) and expired
// records are swept opportunistically on each new flow.
package relay

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

// TTL is how long a login flow may take end to end.
const TTL = 10 * time.Minute

// Mode says what the flow is for.
type Mode string

const (
	ModeLogin Mode = "login" // sign in (JIT-provision on first contact)
	ModeLink  Mode = "link"  // attach a new provider to an existing identity
)

// Flow is the server-side record of one in-progress login.
type Flow struct {
	ID       string
	Provider string
	Mode     Mode
	// Binding is the secret handed to the browser that started the flow (as a
	// cookie) and demanded back at the callback. It is deliberately *not* the
	// flow ID (that rides inside the signed state, through the upstream's URL
	// bar, logs and Referer) and not the nonce (that goes upstream): a party
	// who captures or is handed the callback URL still cannot complete the
	// flow. This is what binds a flow to a user agent — see Consume.
	Binding string
	// Nonce binds the upstream ID token to this flow.
	Nonce string
	// Verifier is the PKCE code verifier; its S256 challenge went upstream.
	Verifier string
	// AppID is the relying application to deliver the assertion to
	// ("" = demo UI only).
	AppID string
	// SessionID is the bridge session initiating a link flow.
	SessionID string
	Expires   time.Time
}

// Errors, comparable with errors.Is.
var (
	ErrBadState     = errors.New("relay: state invalid or tampered")
	ErrStateExpired = errors.New("relay: state expired")
	ErrStateUsed    = errors.New("relay: state already used or unknown (possible replay)")
	ErrUnbound      = errors.New("relay: callback came from a different browser than started the flow")
)

// maxFlows bounds the flow table's memory: /login/{provider} is
// unauthenticated, so an anonymous flood must not grow the map without bound.
// A full table *evicts* rather than refusing, because refusing hands any
// anonymous client a global login outage for a whole TTL for the price of
// maxFlows plain GETs — a worse failure than the memory it was guarding.
// Map iteration order is random and under a flood the flood owns nearly the
// whole table, so a random victim is nearly always the attacker's own flow.
//
// ponytail: random eviction, not LRU — an ordered index only earns its keep if
// legitimate load reaches 50k concurrent logins, and then the cap is the thing
// to raise.
const maxFlows = 50_000

// sweepInterval throttles the opportunistic expiry sweep. Sweeping on *every*
// Begin makes each request O(live flows) under the manager's mutex, so a flood
// costs quadratic time; once every 30s bounds that to a rounding error while
// still keeping abandoned flows from accumulating past TTL by much.
const sweepInterval = 30 * time.Second

// Manager creates and consumes login flows. Safe for concurrent use.
type Manager struct {
	hmacKey []byte
	now     func() time.Time

	mu        sync.Mutex
	flows     map[string]Flow
	lastSweep time.Time
	// evicted counts flows destroyed by saturation since the last sweep tick.
	// An evicted flow's callback later fails as ErrStateUsed and is logged as a
	// possible replay, so without this counter a full table is indistinguishable
	// from an attack. Drained (and logged) on the sweep, which is already
	// throttled — that is what keeps a saturated table from logging per request.
	evicted uint64
}

// NewManager builds a Manager. hmacKey must be at least 32 bytes of secret
// key material; now is injectable for tests (nil = time.Now).
func NewManager(hmacKey []byte, now func() time.Time) (*Manager, error) {
	if len(hmacKey) < 32 {
		return nil, errors.New("relay: HMAC key must be at least 32 bytes")
	}
	if now == nil {
		now = time.Now
	}
	return &Manager{hmacKey: hmacKey, now: now, flows: make(map[string]Flow)}, nil
}

// statePayload is what gets signed into the state parameter.
type statePayload struct {
	ID       string `json:"id"`
	Provider string `json:"p"`
	Exp      int64  `json:"exp"`
}

// Begin creates a flow and returns it with its signed state parameter.
// The returned flow carries a fresh nonce and PKCE verifier; the caller
// derives the S256 challenge via Challenge.
func (m *Manager) Begin(provider string, mode Mode, appID, sessionID string) (Flow, string, error) {
	f := Flow{
		ID:        randomToken(),
		Provider:  provider,
		Mode:      mode,
		Binding:   randomToken(),
		Nonce:     randomToken(),
		Verifier:  randomToken(), // 43 base64url chars: a valid RFC 7636 verifier
		AppID:     appID,
		SessionID: sessionID,
		Expires:   m.now().Add(TTL),
	}
	payload, err := json.Marshal(statePayload{ID: f.ID, Provider: provider, Exp: f.Expires.Unix()})
	if err != nil {
		return Flow{}, "", err
	}
	state := base64.RawURLEncoding.EncodeToString(payload) + "." + m.sign(payload)

	m.mu.Lock()
	defer m.mu.Unlock()
	// Opportunistic sweep: expired flows are garbage, collect them here rather
	// than with a background goroutine — but at most every sweepInterval, so
	// the cost is not paid per request.
	if now := m.now(); now.Sub(m.lastSweep) >= sweepInterval {
		m.lastSweep = now
		if m.evicted > 0 {
			// ponytail: slog.Default(), not a Manager field — same sink the
			// server logs to, and nothing to wire through NewManager.
			slog.Warn("flow table saturated, evicting live flows (their callbacks will log as possible replay)",
				"evicted", m.evicted, "cap", maxFlows)
			m.evicted = 0
		}
		for id, old := range m.flows {
			if now.After(old.Expires) {
				delete(m.flows, id)
			}
		}
	}
	if len(m.flows) >= maxFlows {
		// Make room in O(1) instead of shedding the new flow — see maxFlows.
		m.evicted++
		for id := range m.flows {
			delete(m.flows, id)
			break
		}
	}
	m.flows[f.ID] = f
	return f, state, nil
}

// Consume verifies a state parameter for the given provider and returns its
// flow, deleting it: a state can be consumed exactly once. binding is the
// secret the browser presented (Flow.Binding, held in a cookie); an absent
// cookie is "" and fails like any other mismatch.
//
// Check order matters for the error a caller can trust: signature first
// (everything else in the payload is attacker-controlled until it passes),
// then expiry, then one-time-use, then the browser binding — the binding
// check runs *after* the record is deleted so a wrong-browser callback still
// burns the flow rather than leaving it available for a retry.
func (m *Manager) Consume(state, provider, binding string) (Flow, error) {
	dot := -1
	for i, c := range state {
		if c == '.' {
			dot = i
			break
		}
	}
	if dot < 0 {
		return Flow{}, ErrBadState
	}
	payload, err := base64.RawURLEncoding.DecodeString(state[:dot])
	if err != nil {
		return Flow{}, ErrBadState
	}
	want := m.sign(payload)
	if subtle.ConstantTimeCompare([]byte(want), []byte(state[dot+1:])) != 1 {
		return Flow{}, ErrBadState
	}
	var sp statePayload
	if err := json.Unmarshal(payload, &sp); err != nil {
		return Flow{}, ErrBadState
	}
	if sp.Provider != provider {
		return Flow{}, fmt.Errorf("%w: state was issued for provider %q", ErrBadState, sp.Provider)
	}
	if m.now().Unix() >= sp.Exp {
		return Flow{}, ErrStateExpired
	}
	m.mu.Lock()
	f, ok := m.flows[sp.ID]
	delete(m.flows, sp.ID)
	m.mu.Unlock()
	if !ok {
		return Flow{}, ErrStateUsed
	}
	if m.now().After(f.Expires) {
		return Flow{}, ErrStateExpired
	}
	if subtle.ConstantTimeCompare([]byte(f.Binding), []byte(binding)) != 1 {
		return Flow{}, ErrUnbound
	}
	return f, nil
}

// Challenge derives the PKCE S256 code challenge from a verifier.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func (m *Manager) sign(payload []byte) string {
	mac := hmac.New(sha256.New, m.hmacKey)
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// randomToken returns 32 bytes of CSPRNG output, base64url (43 chars).
func randomToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // rand.Read cannot fail on supported platforms
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
