// Package keystore manages signing key lifecycle: generation, zero-downtime
// rotation, envelope-encrypted persistence, and retirement.
//
// The rotation model is a four-state machine designed so that verifiers never
// see a token signed by a key they haven't had a chance to learn:
//
//	pending ──(dwell elapsed)──► active ──(new key promoted)──► retiring ──(verify window elapsed)──► retired
//
//   - pending: published in the JWKS but never signs. Exists so that every
//     downstream JWKS cache can pick the key up before the first token is
//     signed with it. The dwell time must exceed the JWKS cache TTL.
//   - active: the one key per algorithm that signs new tokens.
//   - retiring: no longer signs, still published for verification until every
//     token it could have signed has expired.
//   - retired: unpublished; private material retained (encrypted) for audit.
package keystore

import (
	"crypto"
	"errors"
	"time"

	"github.com/aikazzh/portfolio/keysmith/jose"
)

// State is a key lifecycle state.
type State string

const (
	StatePending  State = "pending"
	StateActive   State = "active"
	StateRetiring State = "retiring"
	StateRetired  State = "retired"
)

// Key is a managed signing key with lifecycle metadata.
type Key struct {
	ID    string
	Alg   jose.Algorithm
	State State

	CreatedAt  time.Time
	PromotedAt time.Time // when it became active (zero if never)
	RetiringAt time.Time // when it left active
	RetiredAt  time.Time // when it was unpublished

	Private crypto.Signer
	Public  crypto.PublicKey
}

// SigningKey adapts the key for the jose package.
func (k Key) SigningKey() jose.SigningKey {
	return jose.SigningKey{ID: k.ID, Alg: k.Alg, Private: k.Private}
}

// VerificationKey adapts the key for the jose package.
func (k Key) VerificationKey() jose.VerificationKey {
	return jose.VerificationKey{ID: k.ID, Alg: k.Alg, Public: k.Public}
}

// Published reports whether the key belongs in the JWKS document.
func (k Key) Published() bool {
	switch k.State {
	case StatePending, StateActive, StateRetiring:
		return true
	}
	return false
}

// Store errors.
var (
	ErrNotFound  = errors.New("keystore: key not found")
	ErrDuplicate = errors.New("keystore: key already exists")
)
