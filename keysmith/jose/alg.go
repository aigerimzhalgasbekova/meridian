// Package jose implements a deliberately minimal subset of JOSE (JWS compact
// serialization, JWT claims, JWK/JWKS) on top of the Go standard library.
//
// Design stance: this package is allowlist-only. It supports exactly three
// asymmetric signature algorithms and refuses everything else at parse time.
// There is no HMAC support (eliminates key-confusion attacks where an RSA
// public key is reused as an HMAC secret), no "none" algorithm, no negotiation
// of the algorithm from token input (the verifier's key set decides, never the
// token), and no trust in self-describing headers (jwk/jku/x5u/crit are
// rejected outright).
package jose

import "fmt"

// Algorithm identifies a supported JWS signature algorithm.
type Algorithm string

const (
	// AlgEdDSA is Ed25519 (RFC 8037). Preferred: small keys, fast, no
	// parameter or padding choices to get wrong.
	AlgEdDSA Algorithm = "EdDSA"
	// AlgES256 is ECDSA over P-256 with SHA-256 (RFC 7518 §3.4).
	AlgES256 Algorithm = "ES256"
	// AlgRS256 is RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7518 §3.3), supported
	// for ecosystem compatibility. Minimum modulus size is 2048 bits.
	AlgRS256 Algorithm = "RS256"
)

// Supported reports whether a is one of the allowlisted algorithms.
func (a Algorithm) Supported() bool {
	switch a {
	case AlgEdDSA, AlgES256, AlgRS256:
		return true
	}
	return false
}

func (a Algorithm) check() error {
	if !a.Supported() {
		return fmt.Errorf("jose: algorithm %q is not in the allowlist", string(a))
	}
	return nil
}
