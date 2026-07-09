package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"time"

	"github.com/aikazzh/portfolio/keysmith/jose"
)

// Signer mints bridge's app-facing assertions. It is a seam, not an
// abstraction for its own sake: dev and tests use LocalSigner (an in-process
// ephemeral key), while a production deployment injects a signer backed by
// the keysmith service — keysmith/client.Client.Sign already has exactly this
// shape (claims in, compact JWT out), so wiring it is an adapter of a few
// lines and no bridge code changes.
type Signer interface {
	Sign(claims jose.Claims) (string, error)
}

// AssertionTTL bounds the app-facing assertion. It is a message, not a
// session: the app consumes it within one redirect hop and establishes its
// own session, so two minutes is generous.
const AssertionTTL = 2 * time.Minute

// LocalSigner signs assertions with an ephemeral in-process Ed25519 key.
type LocalSigner struct {
	key jose.SigningKey
}

// NewLocalSigner generates a fresh key and returns the signer plus the
// verification key (tests and the dev demo app verify against it).
func NewLocalSigner() (*LocalSigner, jose.VerificationKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, jose.VerificationKey{}, err
	}
	kid, err := jose.Thumbprint(pub)
	if err != nil {
		return nil, jose.VerificationKey{}, err
	}
	return &LocalSigner{key: jose.SigningKey{ID: kid, Alg: jose.AlgEdDSA, Private: priv}},
		jose.VerificationKey{ID: kid, Alg: jose.AlgEdDSA, Public: pub}, nil
}

// Sign implements Signer.
func (s *LocalSigner) Sign(claims jose.Claims) (string, error) {
	return jose.SignClaims(claims, s.key)
}
