package keystore

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aikazzh/portfolio/keysmith/jose"
)

// Config tunes the rotation state machine.
type Config struct {
	// Algorithms this manager maintains an active key for.
	Algorithms []jose.Algorithm

	// PendingDwell is how long a new key stays pending (published, not
	// signing) before it may be promoted. MUST exceed the JWKS cache TTL
	// served to verifiers, or rotation stops being zero-downtime.
	PendingDwell time.Duration

	// MaxKeyAge is how long a key signs before rotation begins.
	MaxKeyAge time.Duration

	// RetireAfter is how long a demoted key stays published for
	// verification. MUST be at least the maximum lifetime of any token the
	// key could have signed.
	RetireAfter time.Duration

	// RSABits sets the modulus size for generated RSA keys (default 2048).
	RSABits int

	// Now supplies the clock; defaults to time.Now. Injectable for tests.
	Now func() time.Time

	// Audit receives lifecycle events. Optional.
	Audit func(Event)
}

// Event records a key lifecycle operation.
type Event struct {
	Time   time.Time         `json:"time"`
	Op     string            `json:"op"` // generated | promoted | demoted | retired | revoked
	KeyID  string            `json:"key_id"`
	Alg    jose.Algorithm    `json:"alg"`
	Detail map[string]string `json:"detail,omitempty"`
}

// Manager errors.
var (
	ErrNoActiveKey     = errors.New("keystore: no active key for algorithm")
	ErrNotPending      = errors.New("keystore: key is not pending")
	ErrDwellNotElapsed = errors.New("keystore: pending dwell has not elapsed")
	ErrAlreadyRetired  = errors.New("keystore: key is already retired")
)

// Manager drives the key lifecycle over a Store. All mutations are serialized;
// reads go straight to the store.
type Manager struct {
	store Store
	cfg   Config
	mu    sync.Mutex
}

// NewManager validates cfg and builds a Manager.
func NewManager(store Store, cfg Config) (*Manager, error) {
	if len(cfg.Algorithms) == 0 {
		return nil, errors.New("keystore: at least one algorithm required")
	}
	for _, a := range cfg.Algorithms {
		if !a.Supported() {
			return nil, fmt.Errorf("keystore: unsupported algorithm %q", a)
		}
	}
	if cfg.PendingDwell <= 0 || cfg.MaxKeyAge <= 0 || cfg.RetireAfter <= 0 {
		return nil, errors.New("keystore: PendingDwell, MaxKeyAge and RetireAfter must be positive")
	}
	if cfg.PendingDwell >= cfg.MaxKeyAge {
		return nil, errors.New("keystore: PendingDwell must be shorter than MaxKeyAge")
	}
	if cfg.RSABits == 0 {
		cfg.RSABits = 2048
	}
	if cfg.RSABits < jose.MinRSABits {
		return nil, fmt.Errorf("keystore: RSABits %d below minimum %d", cfg.RSABits, jose.MinRSABits)
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Manager{store: store, cfg: cfg}, nil
}

func (m *Manager) emit(op string, k Key, detail map[string]string) {
	if m.cfg.Audit == nil {
		return
	}
	m.cfg.Audit(Event{Time: m.cfg.Now(), Op: op, KeyID: k.ID, Alg: k.Alg, Detail: detail})
}

// Generate creates a new pending key for alg.
func (m *Manager) Generate(ctx context.Context, alg jose.Algorithm) (Key, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.generateLocked(ctx, alg)
}

func (m *Manager) generateLocked(ctx context.Context, alg jose.Algorithm) (Key, error) {
	k, err := newKey(alg, m.cfg.RSABits, m.cfg.Now())
	if err != nil {
		return Key{}, err
	}
	if err := m.store.Put(ctx, k); err != nil {
		return Key{}, err
	}
	m.emit("generated", k, nil)
	return k, nil
}

func newKey(alg jose.Algorithm, rsaBits int, now time.Time) (Key, error) {
	k := Key{Alg: alg, State: StatePending, CreatedAt: now}
	switch alg {
	case jose.AlgEdDSA:
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return Key{}, err
		}
		k.Private, k.Public = priv, pub
	case jose.AlgES256:
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return Key{}, err
		}
		k.Private, k.Public = priv, &priv.PublicKey
	case jose.AlgRS256:
		priv, err := rsa.GenerateKey(rand.Reader, rsaBits)
		if err != nil {
			return Key{}, err
		}
		k.Private, k.Public = priv, &priv.PublicKey
	default:
		return Key{}, fmt.Errorf("keystore: unsupported algorithm %q", alg)
	}
	id, err := jose.Thumbprint(k.Public)
	if err != nil {
		return Key{}, err
	}
	k.ID = id
	return k, nil
}

// Promote makes a pending key the active signer for its algorithm, demoting
// the current active key to retiring. Refuses to promote before PendingDwell
// has elapsed unless force is set (or no active key exists — availability
// beats cache warmth on cold start).
func (m *Manager) Promote(ctx context.Context, id string, force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.promoteLocked(ctx, id, force)
}

func (m *Manager) promoteLocked(ctx context.Context, id string, force bool) error {
	now := m.cfg.Now()
	k, err := m.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if k.State != StatePending {
		return fmt.Errorf("%w: %q is %s", ErrNotPending, id, k.State)
	}
	active, activeErr := m.activeLocked(ctx, k.Alg)
	hasActive := activeErr == nil
	if !force && hasActive && now.Sub(k.CreatedAt) < m.cfg.PendingDwell {
		return fmt.Errorf("%w: %s remaining", ErrDwellNotElapsed, m.cfg.PendingDwell-now.Sub(k.CreatedAt))
	}
	prev := active
	if hasActive {
		active.State = StateRetiring
		active.RetiringAt = now
		if err := m.store.Update(ctx, active); err != nil {
			return err
		}
		m.emit("demoted", active, map[string]string{"successor": k.ID})
	}
	k.State = StateActive
	k.PromotedAt = now
	if err := m.store.Update(ctx, k); err != nil {
		// The demotion already committed durably. Leaving it would strand the
		// algorithm with no active key — every sign 503s — until the next Tick
		// force-promotes, and that recovery bypasses the pending dwell. There
		// is no transaction across the two writes, so compensate by hand.
		if hasActive {
			if rerr := m.store.Update(ctx, prev); rerr != nil {
				m.emit("demote_rollback_failed", prev, map[string]string{"err": rerr.Error()})
			}
		}
		return err
	}
	m.emit("promoted", k, nil)
	return nil
}

// Revoke immediately unpublishes a key and, if it was the active signer,
// promotes a successor in the same call.
//
// This is the containment for a confirmed private-key compromise, which the
// ordinary lifecycle cannot express: demotion leaves the key published for
// RetireAfter so that tokens it already signed keep verifying, but an attacker
// holding the private half mints *new* tokens, so that window is their runway,
// not a safety margin. Revocation drops the key from the JWKS now and accepts
// that genuine in-flight tokens signed by it stop verifying.
func (m *Manager) Revoke(ctx context.Context, id, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, err := m.store.Get(ctx, id)
	if err != nil {
		return err
	}
	if k.State == StateRetired {
		return fmt.Errorf("%w: %q", ErrAlreadyRetired, id)
	}
	if k.State == StateActive {
		// Revoking the signer would otherwise hand the operator an outage
		// instead of a containment. Prefer the newest pending key (verifier
		// caches have already warmed on it); generate one only if there is
		// none. Forced, because a compromise cannot wait out the dwell.
		//
		// Promote the successor BEFORE committing the retirement: if any step
		// here fails, nothing has changed yet and the revoke is cleanly
		// retryable — committing retirement first would leave the platform
		// with zero active signing keys (every sign 503s) on a transient
		// failure, with the retry answering already_retired.
		keys, err := m.store.List(ctx)
		if err != nil {
			return err
		}
		var successor *Key
		for i := range keys {
			if keys[i].Alg == k.Alg && keys[i].State == StatePending &&
				(successor == nil || keys[i].CreatedAt.After(successor.CreatedAt)) {
				successor = &keys[i]
			}
		}
		if successor == nil {
			fresh, err := m.generateLocked(ctx, k.Alg)
			if err != nil {
				return err
			}
			successor = &fresh
		}
		if err := m.promoteLocked(ctx, successor.ID, true); err != nil {
			return err
		}
		// promoteLocked demoted k to retiring; re-read so the retirement below
		// updates the current row rather than clobbering it with stale state.
		if k, err = m.store.Get(ctx, id); err != nil {
			return err
		}
	}
	now := m.cfg.Now()
	if k.RetiringAt.IsZero() {
		k.RetiringAt = now
	}
	k.State, k.RetiredAt = StateRetired, now
	if err := m.store.Update(ctx, k); err != nil {
		return err
	}
	m.emit("revoked", k, map[string]string{"reason": reason})
	return nil
}

// Config returns the configuration this manager actually holds, post-defaults.
// Callers that must enforce invariants against it (service.New) read it here
// rather than trusting a Config value passed alongside the manager, which can
// silently disagree.
func (m *Manager) Config() Config { return m.cfg }

func (m *Manager) activeLocked(ctx context.Context, alg jose.Algorithm) (Key, error) {
	keys, err := m.store.List(ctx)
	if err != nil {
		return Key{}, err
	}
	for _, k := range keys {
		if k.Alg == alg && k.State == StateActive {
			return k, nil
		}
	}
	return Key{}, fmt.Errorf("%w: %s", ErrNoActiveKey, alg)
}

// SigningKey returns the active signing key for alg.
func (m *Manager) SigningKey(ctx context.Context, alg jose.Algorithm) (jose.SigningKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, err := m.activeLocked(ctx, alg)
	if err != nil {
		return jose.SigningKey{}, err
	}
	return k.SigningKey(), nil
}

// Keys lists all managed keys.
func (m *Manager) Keys(ctx context.Context) ([]Key, error) {
	return m.store.List(ctx)
}

// VerificationSet returns a resolver over every published key.
func (m *Manager) VerificationSet(ctx context.Context) (*jose.KeySet, error) {
	keys, err := m.store.List(ctx)
	if err != nil {
		return nil, err
	}
	var vks []jose.VerificationKey
	for _, k := range keys {
		if k.Published() {
			vks = append(vks, k.VerificationKey())
		}
	}
	return jose.NewKeySet(vks...)
}

// JWKS renders the published keys as a JWK Set document.
func (m *Manager) JWKS(ctx context.Context) (jose.JWKS, error) {
	keys, err := m.store.List(ctx)
	if err != nil {
		return jose.JWKS{}, err
	}
	set := jose.JWKS{Keys: []jose.JWK{}}
	for _, k := range keys {
		if !k.Published() {
			continue
		}
		j, err := jose.PublicJWK(k.VerificationKey())
		if err != nil {
			return jose.JWKS{}, err
		}
		set.Keys = append(set.Keys, j)
	}
	return set, nil
}

// Tick advances the state machine one step. Run it periodically (the service
// runs it once a minute). Each call:
//
//  1. Cold start: no keys at all for an algorithm → generate + promote now.
//  2. Availability: pending exists but no active → promote immediately.
//  3. Pre-rotation: active key old enough that a successor should start its
//     dwell → generate a pending key.
//  4. Rotation: pending key past dwell and active past MaxKeyAge → promote.
//  5. Retirement: retiring keys past RetireAfter → retired (unpublished).
func (m *Manager) Tick(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.cfg.Now()
	keys, err := m.store.List(ctx)
	if err != nil {
		return err
	}

	byAlg := make(map[jose.Algorithm]struct {
		active, pending *Key
	})
	for i := range keys {
		k := keys[i]
		entry := byAlg[k.Alg]
		switch k.State {
		case StateActive:
			entry.active = &keys[i]
		case StatePending:
			// Track the newest pending key.
			if entry.pending == nil || k.CreatedAt.After(entry.pending.CreatedAt) {
				entry.pending = &keys[i]
			}
		}
		byAlg[k.Alg] = entry

		if k.State == StateRetiring && !k.RetiringAt.IsZero() && now.Sub(k.RetiringAt) >= m.cfg.RetireAfter {
			k.State = StateRetired
			k.RetiredAt = now
			if err := m.store.Update(ctx, k); err != nil {
				return err
			}
			m.emit("retired", k, nil)
		}
	}

	for _, alg := range m.cfg.Algorithms {
		entry := byAlg[alg]
		switch {
		case entry.active == nil && entry.pending == nil:
			k, err := m.generateLocked(ctx, alg)
			if err != nil {
				return err
			}
			if err := m.promoteLocked(ctx, k.ID, true); err != nil {
				return err
			}

		case entry.active == nil && entry.pending != nil:
			if err := m.promoteLocked(ctx, entry.pending.ID, true); err != nil {
				return err
			}

		case entry.active != nil:
			activeAge := now.Sub(entry.active.PromotedAt)
			if entry.pending == nil && activeAge >= m.cfg.MaxKeyAge-m.cfg.PendingDwell {
				if _, err := m.generateLocked(ctx, alg); err != nil {
					return err
				}
			}
			if entry.pending != nil &&
				now.Sub(entry.pending.CreatedAt) >= m.cfg.PendingDwell &&
				activeAge >= m.cfg.MaxKeyAge {
				if err := m.promoteLocked(ctx, entry.pending.ID, false); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
