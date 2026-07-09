// Package directory is bridge's local identity store: the identities created
// by just-in-time provisioning and their links to upstream providers.
//
// # The one rule that matters
//
// An upstream login maps to a local identity by the pair (provider, subject)
// and by nothing else — never by email. Email is an attribute an upstream
// asserts, not an identifier bridge can trust across providers: many IdPs let
// the account holder change it, some let it go unverified, and an email
// released by one provider can be re-registered at another. Matching by email
// would let whoever controls alice@example.com at provider B silently become
// the alice who signed up via provider A — a classic federated
// account-takeover. See docs/adr/0001.
//
// Consequence: the same human arriving via two providers gets two separate
// identities until they explicitly link them (a flow that requires being
// signed in to one and freshly authenticating to the other). Bridge surfaces
// the collision as a hint, but never merges on its own.
package directory

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Identity is a local bridge identity.
type Identity struct {
	ID        string
	Email     string // display attribute from first login; not an identifier
	Name      string
	CreatedAt time.Time
}

// Link ties an upstream (provider, subject) to a local identity.
type Link struct {
	Provider string
	Subject  string
	Email    string // email as asserted by this provider at link time
	LinkedAt time.Time
}

// Errors, comparable with errors.Is.
var (
	ErrNotFound      = errors.New("directory: identity not found")
	ErrAlreadyLinked = errors.New("directory: this upstream account is already linked to an identity")
)

// Store persists identities and links. The in-memory implementation below
// serves tests and dev mode; a Postgres implementation slots in behind the
// same interface (mirroring idp's storage split).
type Store interface {
	// IdentityByLink resolves an upstream (provider, subject) to its local
	// identity. This — and only this — is the login-time matching rule.
	IdentityByLink(provider, subject string) (Identity, error)
	// CreateIdentity provisions a new identity with its first link.
	CreateIdentity(email, name string, first Link) (Identity, error)
	// AddLink attaches an additional provider to an existing identity.
	// Fails with ErrAlreadyLinked if (provider, subject) is linked anywhere.
	AddLink(identityID string, l Link) error
	// Identity fetches by local ID.
	Identity(id string) (Identity, error)
	// Links lists an identity's provider links.
	Links(identityID string) ([]Link, error)
	// IdentitiesByEmail lists identities whose recorded email matches. Used
	// only to *surface* a possible same-person collision on the account page
	// — never to match logins.
	IdentitiesByEmail(email string) ([]Identity, error)
}

// MemStore is the in-memory Store.
type MemStore struct {
	mu         sync.Mutex
	identities map[string]Identity
	links      map[string]string // provider "\x00" subject -> identity ID
	byIdentity map[string][]Link // identity ID -> links
	now        func() time.Time
}

// NewMemStore builds an empty MemStore. now is injectable (nil = time.Now).
func NewMemStore(now func() time.Time) *MemStore {
	if now == nil {
		now = time.Now
	}
	return &MemStore{
		identities: make(map[string]Identity),
		links:      make(map[string]string),
		byIdentity: make(map[string][]Link),
		now:        now,
	}
}

func linkKey(provider, subject string) string { return provider + "\x00" + subject }

func (s *MemStore) IdentityByLink(provider, subject string) (Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.links[linkKey(provider, subject)]
	if !ok {
		return Identity{}, ErrNotFound
	}
	return s.identities[id], nil
}

func (s *MemStore) CreateIdentity(email, name string, first Link) (Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := linkKey(first.Provider, first.Subject)
	if _, taken := s.links[key]; taken {
		return Identity{}, ErrAlreadyLinked
	}
	b := make([]byte, 16)
	rand.Read(b)
	ident := Identity{
		ID:        "idn_" + base64.RawURLEncoding.EncodeToString(b),
		Email:     email,
		Name:      name,
		CreatedAt: s.now(),
	}
	first.LinkedAt = s.now()
	s.identities[ident.ID] = ident
	s.links[key] = ident.ID
	s.byIdentity[ident.ID] = []Link{first}
	return ident, nil
}

func (s *MemStore) AddLink(identityID string, l Link) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.identities[identityID]; !ok {
		return ErrNotFound
	}
	key := linkKey(l.Provider, l.Subject)
	if owner, taken := s.links[key]; taken {
		return fmt.Errorf("%w (identity %s)", ErrAlreadyLinked, owner)
	}
	l.LinkedAt = s.now()
	s.links[key] = identityID
	s.byIdentity[identityID] = append(s.byIdentity[identityID], l)
	return nil
}

func (s *MemStore) Identity(id string) (Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ident, ok := s.identities[id]
	if !ok {
		return Identity{}, ErrNotFound
	}
	return ident, nil
}

func (s *MemStore) Links(identityID string) ([]Link, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.identities[identityID]; !ok {
		return nil, ErrNotFound
	}
	out := make([]Link, len(s.byIdentity[identityID]))
	copy(out, s.byIdentity[identityID])
	return out, nil
}

func (s *MemStore) IdentitiesByEmail(email string) ([]Identity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Identity
	for _, ident := range s.identities {
		if ident.Email == email && email != "" {
			out = append(out, ident)
		}
	}
	return out, nil
}
