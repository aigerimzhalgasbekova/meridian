package jose

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
)

// Strict: the decoder must reject non-canonical encodings. Without it the
// unused trailing bits of a final base64 quantum are ignored, so a 64-byte
// Ed25519 signature has 16 distinct encodings that all decode to the same
// bytes — i.e. a token's identity as a string diverges from its identity as a
// credential, and any consumer keying a replay cache or denylist on the raw
// token string is bypassed by re-encoding one character.
var b64 = base64.RawURLEncoding.Strict()

// MinRSABits is the smallest RSA modulus this package will sign or verify with.
const MinRSABits = 2048

// MaxRSABits is the largest RSA modulus this package will verify with.
// Modular exponentiation cost grows superlinearly in the modulus size, so an
// unbounded modulus in a JWKS we do not control (a federated IdP's) is remote
// CPU exhaustion: 8192 bits verifies in under 2ms, 65536 takes 60ms.
const MaxRSABits = 8192

// checkRSABits bounds an RSA modulus on both sides. Every RSA path in this
// package routes through it so the two bounds cannot drift apart.
func checkRSABits(bits int) error {
	if bits < MinRSABits || bits > MaxRSABits {
		return fmt.Errorf("jose: RSA key is %d bits, must be between %d and %d", bits, MinRSABits, MaxRSABits)
	}
	return nil
}

// Header is the JOSE protected header. Fields beyond alg/kid/typ exist only so
// their presence can be detected and rejected: this package never dereferences
// keys or URLs supplied by the token itself.
type Header struct {
	Alg Algorithm `json:"alg"`
	Kid string    `json:"kid,omitempty"`
	Typ string    `json:"typ,omitempty"`

	Crit []string        `json:"crit,omitempty"`
	Jwk  json.RawMessage `json:"jwk,omitempty"`
	Jku  string          `json:"jku,omitempty"`
	X5u  string          `json:"x5u,omitempty"`
	X5c  []string        `json:"x5c,omitempty"`
}

// prohibitedHeaders are rejected whenever the member is present, whatever its
// value. Keep in sync with the Header fields above.
var prohibitedHeaders = []string{"crit", "jwk", "jku", "x5u", "x5c"}

// SigningKey couples a private key with its algorithm and key ID.
type SigningKey struct {
	ID      string
	Alg     Algorithm
	Private crypto.Signer
}

// VerificationKey couples a public key with its algorithm and key ID.
type VerificationKey struct {
	ID     string
	Alg    Algorithm
	Public crypto.PublicKey
}

// KeyResolver returns the verification key for a key ID, or an error if the
// key is unknown. Implementations must not trust any input beyond the ID.
type KeyResolver interface {
	VerificationKey(kid string) (VerificationKey, error)
}

// Common verification errors, comparable with errors.Is.
var (
	ErrMalformed        = errors.New("jose: malformed token")
	ErrHeaderRejected   = errors.New("jose: prohibited header parameter")
	ErrAlgNotAllowed    = errors.New("jose: algorithm not allowed")
	ErrKidMissing       = errors.New("jose: kid header missing")
	ErrUnknownKey       = errors.New("jose: unknown key")
	ErrAlgMismatch      = errors.New("jose: token alg does not match key alg")
	ErrSignatureInvalid = errors.New("jose: signature verification failed")
)

// Sign produces a JWS compact serialization of payload under key.
// The header is fixed to {alg, kid, typ: "JWT"}: callers cannot inject
// header parameters.
func Sign(payload []byte, key SigningKey) (string, error) {
	if err := key.Alg.check(); err != nil {
		return "", err
	}
	if key.ID == "" {
		return "", errors.New("jose: signing key has no ID")
	}
	if key.Private == nil {
		return "", errors.New("jose: signing key has no private key")
	}
	hdr, err := json.Marshal(Header{Alg: key.Alg, Kid: key.ID, Typ: "JWT"})
	if err != nil {
		return "", fmt.Errorf("jose: marshal header: %w", err)
	}
	signingInput := b64.EncodeToString(hdr) + "." + b64.EncodeToString(payload)
	sig, err := sign(key, []byte(signingInput))
	if err != nil {
		return "", err
	}
	return signingInput + "." + b64.EncodeToString(sig), nil
}

func sign(key SigningKey, signingInput []byte) ([]byte, error) {
	switch key.Alg {
	case AlgEdDSA:
		priv, ok := key.Private.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("jose: EdDSA requires an ed25519 private key, got %T", key.Private)
		}
		return ed25519.Sign(priv, signingInput), nil

	case AlgES256:
		priv, ok := key.Private.(*ecdsa.PrivateKey)
		if !ok || priv.Curve.Params().Name != "P-256" {
			return nil, fmt.Errorf("jose: ES256 requires a P-256 private key, got %T", key.Private)
		}
		digest := sha256.Sum256(signingInput)
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest[:])
		if err != nil {
			return nil, fmt.Errorf("jose: ecdsa sign: %w", err)
		}
		// JWS wants raw r||s, each left-padded to the curve byte size (32).
		sig := make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
		return sig, nil

	case AlgRS256:
		priv, ok := key.Private.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("jose: RS256 requires an RSA private key, got %T", key.Private)
		}
		if err := checkRSABits(priv.N.BitLen()); err != nil {
			return nil, err
		}
		digest := sha256.Sum256(signingInput)
		sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
		if err != nil {
			return nil, fmt.Errorf("jose: rsa sign: %w", err)
		}
		return sig, nil
	}
	return nil, key.Alg.check()
}

// Verify checks a JWS compact serialization and returns the payload and parsed
// header on success.
//
// The verification policy is strict and non-negotiable:
//   - the token's alg must be in the caller's allowed set,
//   - crit, jwk, jku, x5u and x5c headers cause rejection,
//   - kid is mandatory and must resolve through the caller's resolver,
//   - the resolved key's algorithm must equal the token's alg (the key set,
//     not the token, is the authority on which algorithm applies).
func Verify(token string, resolver KeyResolver, allowed []Algorithm) ([]byte, Header, error) {
	var zero Header
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, zero, fmt.Errorf("%w: expected 3 segments, got %d", ErrMalformed, len(parts))
	}
	rawHeader, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, zero, fmt.Errorf("%w: header segment: %v", ErrMalformed, err)
	}
	// Prohibited members are rejected on *presence in the raw JSON*, not on the
	// decoded struct: `"crit":null`, `"crit":[]` or a duplicate member whose
	// last occurrence is null all decode to a zero value, so a struct check
	// silently ignores a crit header the profile promises to hard-reject.
	var members map[string]json.RawMessage
	if err := json.Unmarshal(rawHeader, &members); err != nil {
		return nil, zero, fmt.Errorf("%w: header not valid for this profile: %v", ErrHeaderRejected, err)
	}
	for _, name := range prohibitedHeaders {
		if _, present := members[name]; present {
			return nil, zero, fmt.Errorf("%w: %q is not accepted", ErrHeaderRejected, name)
		}
	}
	var hdr Header
	dec := json.NewDecoder(strings.NewReader(string(rawHeader)))
	dec.DisallowUnknownFields() // unknown header params are rejected, not ignored
	if err := dec.Decode(&hdr); err != nil {
		return nil, zero, fmt.Errorf("%w: header not valid for this profile: %v", ErrHeaderRejected, err)
	}
	if !algAllowed(hdr.Alg, allowed) {
		return nil, zero, fmt.Errorf("%w: %q", ErrAlgNotAllowed, string(hdr.Alg))
	}
	if hdr.Kid == "" {
		return nil, zero, ErrKidMissing
	}
	key, err := resolver.VerificationKey(hdr.Kid)
	if err != nil {
		return nil, zero, fmt.Errorf("%w: kid %q: %v", ErrUnknownKey, hdr.Kid, err)
	}
	if key.Alg != hdr.Alg {
		return nil, zero, fmt.Errorf("%w: token %q, key %q", ErrAlgMismatch, string(hdr.Alg), string(key.Alg))
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, zero, fmt.Errorf("%w: signature segment: %v", ErrMalformed, err)
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	if err := verify(key, signingInput, sig); err != nil {
		return nil, zero, err
	}
	payload, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, zero, fmt.Errorf("%w: payload segment: %v", ErrMalformed, err)
	}
	return payload, hdr, nil
}

func algAllowed(a Algorithm, allowed []Algorithm) bool {
	if !a.Supported() {
		return false
	}
	for _, want := range allowed {
		if a == want {
			return true
		}
	}
	return false
}

func verify(key VerificationKey, signingInput, sig []byte) error {
	switch key.Alg {
	case AlgEdDSA:
		pub, ok := key.Public.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("jose: EdDSA requires an ed25519 public key, got %T", key.Public)
		}
		if !ed25519.Verify(pub, signingInput, sig) {
			return ErrSignatureInvalid
		}
		return nil

	case AlgES256:
		pub, ok := key.Public.(*ecdsa.PublicKey)
		if !ok || pub.Curve.Params().Name != "P-256" {
			return fmt.Errorf("jose: ES256 requires a P-256 public key, got %T", key.Public)
		}
		if len(sig) != 64 {
			return fmt.Errorf("%w: ES256 signature must be 64 bytes, got %d", ErrSignatureInvalid, len(sig))
		}
		digest := sha256.Sum256(signingInput)
		r := new(big.Int).SetBytes(sig[:32])
		s := new(big.Int).SetBytes(sig[32:])
		if !ecdsa.Verify(pub, digest[:], r, s) {
			return ErrSignatureInvalid
		}
		return nil

	case AlgRS256:
		pub, ok := key.Public.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("jose: RS256 requires an RSA public key, got %T", key.Public)
		}
		if err := checkRSABits(pub.N.BitLen()); err != nil {
			return err
		}
		digest := sha256.Sum256(signingInput)
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
			return ErrSignatureInvalid
		}
		return nil
	}
	return key.Alg.check()
}
