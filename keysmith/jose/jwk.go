package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

// JWK is a public JSON Web Key (RFC 7517). This package only ever marshals
// public key material; private JWK serialization is intentionally absent —
// private keys leave keysmith only through the encrypted keystore.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use,omitempty"`
	Alg string `json:"alg,omitempty"`

	// OKP (Ed25519)
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	// EC additionally uses Y
	Y string `json:"y,omitempty"`
	// RSA
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
}

// JWKS is a JWK Set document.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// PublicJWK encodes a verification key as a public JWK.
func PublicJWK(key VerificationKey) (JWK, error) {
	jwk := JWK{Kid: key.ID, Use: "sig", Alg: string(key.Alg)}
	// The declared alg must match the concrete key type, or this encoder emits
	// a JWK its own PublicKey decoder refuses (e.g. kty=OKP with alg=RS256).
	switch pub := key.Public.(type) {
	case ed25519.PublicKey:
		if key.Alg != AlgEdDSA {
			return JWK{}, fmt.Errorf("%w: Ed25519 key with alg %q", ErrAlgMismatch, key.Alg)
		}
		jwk.Kty, jwk.Crv = "OKP", "Ed25519"
		jwk.X = b64.EncodeToString(pub)
	case *ecdsa.PublicKey:
		if key.Alg != AlgES256 {
			return JWK{}, fmt.Errorf("%w: EC key with alg %q", ErrAlgMismatch, key.Alg)
		}
		if pub.Curve.Params().Name != "P-256" {
			return JWK{}, fmt.Errorf("jose: unsupported curve %q", pub.Curve.Params().Name)
		}
		jwk.Kty, jwk.Crv = "EC", "P-256"
		buf := make([]byte, 32)
		jwk.X = b64.EncodeToString(pub.X.FillBytes(buf))
		buf2 := make([]byte, 32)
		jwk.Y = b64.EncodeToString(pub.Y.FillBytes(buf2))
	case *rsa.PublicKey:
		if key.Alg != AlgRS256 {
			return JWK{}, fmt.Errorf("%w: RSA key with alg %q", ErrAlgMismatch, key.Alg)
		}
		if err := checkRSABits(pub.N.BitLen()); err != nil {
			return JWK{}, err
		}
		jwk.Kty = "RSA"
		jwk.N = b64.EncodeToString(pub.N.Bytes())
		jwk.E = b64.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	default:
		return JWK{}, fmt.Errorf("jose: unsupported public key type %T", key.Public)
	}
	return jwk, nil
}

// PublicKey decodes the JWK into a VerificationKey.
func (j JWK) PublicKey() (VerificationKey, error) {
	if j.Kid == "" {
		return VerificationKey{}, errors.New("jose: JWK has no kid")
	}
	alg := Algorithm(j.Alg)
	if err := alg.check(); err != nil {
		return VerificationKey{}, err
	}
	var pub crypto.PublicKey
	switch {
	case j.Kty == "OKP" && j.Crv == "Ed25519":
		if alg != AlgEdDSA {
			return VerificationKey{}, fmt.Errorf("%w: OKP key with alg %q", ErrAlgMismatch, j.Alg)
		}
		x, err := b64.DecodeString(j.X)
		if err != nil || len(x) != ed25519.PublicKeySize {
			return VerificationKey{}, errors.New("jose: invalid Ed25519 x coordinate")
		}
		pub = ed25519.PublicKey(x)
	case j.Kty == "EC" && j.Crv == "P-256":
		if alg != AlgES256 {
			return VerificationKey{}, fmt.Errorf("%w: EC key with alg %q", ErrAlgMismatch, j.Alg)
		}
		xb, err1 := b64.DecodeString(j.X)
		yb, err2 := b64.DecodeString(j.Y)
		if err1 != nil || err2 != nil {
			return VerificationKey{}, errors.New("jose: invalid EC coordinates")
		}
		x, y := new(big.Int).SetBytes(xb), new(big.Int).SetBytes(yb)
		// Point-on-curve check: never accept an off-curve public key.
		if !elliptic.P256().IsOnCurve(x, y) {
			return VerificationKey{}, errors.New("jose: EC point is not on P-256")
		}
		pub = &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	case j.Kty == "RSA":
		if alg != AlgRS256 {
			return VerificationKey{}, fmt.Errorf("%w: RSA key with alg %q", ErrAlgMismatch, j.Alg)
		}
		nb, err1 := b64.DecodeString(j.N)
		eb, err2 := b64.DecodeString(j.E)
		if err1 != nil || err2 != nil {
			return VerificationKey{}, errors.New("jose: invalid RSA parameters")
		}
		n := new(big.Int).SetBytes(nb)
		if err := checkRSABits(n.BitLen()); err != nil {
			return VerificationKey{}, err
		}
		e := new(big.Int).SetBytes(eb)
		if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
			return VerificationKey{}, errors.New("jose: RSA exponent out of range")
		}
		pub = &rsa.PublicKey{N: n, E: int(e.Int64())}
	default:
		return VerificationKey{}, fmt.Errorf("jose: unsupported kty/crv %q/%q", j.Kty, j.Crv)
	}
	return VerificationKey{ID: j.Kid, Alg: alg, Public: pub}, nil
}

// KeySet is an immutable set of verification keys implementing KeyResolver.
type KeySet struct {
	byID map[string]VerificationKey
}

// NewKeySet builds a KeySet, rejecting duplicate kids.
func NewKeySet(keys ...VerificationKey) (*KeySet, error) {
	byID := make(map[string]VerificationKey, len(keys))
	for _, k := range keys {
		if k.ID == "" {
			return nil, errors.New("jose: key without ID")
		}
		if _, dup := byID[k.ID]; dup {
			return nil, fmt.Errorf("jose: duplicate kid %q", k.ID)
		}
		byID[k.ID] = k
	}
	return &KeySet{byID: byID}, nil
}

// ParseJWKS decodes a JWKS document into a KeySet, skipping keys this profile
// cannot use and failing only if that leaves nothing.
//
// All-or-nothing is right for a single key and wrong for a key *set*: a set is
// heterogeneous by nature (RFC 7517 makes `alg` optional, and providers mix
// algorithms), and this parser is fed JWKS documents from federated identity
// providers we neither control nor constrain. One unusable key must not take
// the usable ones down with it — an unusable key is still never accepted.
func ParseJWKS(doc []byte) (*KeySet, error) {
	var set JWKS
	if err := json.Unmarshal(doc, &set); err != nil {
		return nil, fmt.Errorf("jose: parse JWKS: %w", err)
	}
	keys := make([]VerificationKey, 0, len(set.Keys))
	var rejected int
	var firstErr error
	for _, j := range set.Keys {
		k, err := j.PublicKey()
		if err != nil {
			rejected++
			if firstErr == nil {
				firstErr = fmt.Errorf("jose: JWKS key %q: %w", j.Kid, err)
			}
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 && rejected > 0 {
		return nil, fmt.Errorf("jose: parse JWKS: no usable keys (%d rejected): %w", rejected, firstErr)
	}
	return NewKeySet(keys...)
}

// VerificationKey implements KeyResolver.
func (s *KeySet) VerificationKey(kid string) (VerificationKey, error) {
	k, ok := s.byID[kid]
	if !ok {
		return VerificationKey{}, ErrUnknownKey
	}
	return k, nil
}

// Len reports the number of keys in the set.
func (s *KeySet) Len() int { return len(s.byID) }

// Thumbprint computes the RFC 7638 JWK thumbprint (SHA-256, base64url) of the
// key. Used as the canonical key ID: it is stable, collision-resistant, and
// derived from the key material itself.
func Thumbprint(pub crypto.PublicKey) (string, error) {
	// RFC 7638 §3: required members only, lexicographic order, no whitespace.
	var canonical string
	switch p := pub.(type) {
	case ed25519.PublicKey:
		canonical = fmt.Sprintf(`{"crv":"Ed25519","kty":"OKP","x":"%s"}`, b64.EncodeToString(p))
	case *ecdsa.PublicKey:
		if p.Curve.Params().Name != "P-256" {
			return "", fmt.Errorf("jose: unsupported curve %q", p.Curve.Params().Name)
		}
		x, y := make([]byte, 32), make([]byte, 32)
		canonical = fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":"%s","y":"%s"}`,
			b64.EncodeToString(p.X.FillBytes(x)), b64.EncodeToString(p.Y.FillBytes(y)))
	case *rsa.PublicKey:
		canonical = fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`,
			b64.EncodeToString(big.NewInt(int64(p.E)).Bytes()), b64.EncodeToString(p.N.Bytes()))
	default:
		return "", fmt.Errorf("jose: unsupported public key type %T", pub)
	}
	sum := sha256.Sum256([]byte(canonical))
	return b64.EncodeToString(sum[:]), nil
}
