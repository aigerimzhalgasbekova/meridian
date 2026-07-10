// Package auth verifies the bearer tokens that authenticate console admins.
//
// The server depends only on the Verifier interface. HS256 with a static
// shared key is the local/dev/test implementation; production wires a
// verifier backed by keysmith's JWKS (Ed25519, kid-pinned) — the same seam
// idp uses. The interface is one method precisely so that swap is trivial.
//
// The HS256 implementation is deliberately strict: the algorithm is pinned
// (the token's alg header must equal HS256 — no negotiation from token
// input), exp is required, and signatures are compared in constant time.
package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Verifier authenticates a bearer token and returns the subject it was
// issued to.
type Verifier interface {
	Verify(token string) (subject string, err error)
}

// HS256 verifies (and, for dev seeding, mints) HS256 JWTs with a static key.
type HS256 struct {
	Key []byte
	Now func() time.Time // nil means time.Now
}

var errInvalid = errors.New("invalid token")

func (h HS256) now() time.Time {
	if h.Now != nil {
		return h.Now()
	}
	return time.Now()
}

func (h HS256) sign(signingInput string) []byte {
	mac := hmac.New(sha256.New, h.Key)
	mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}

// Verify checks signature, algorithm, and expiry, returning the sub claim.
func (h HS256) Verify(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", errInvalid
	}
	var header struct {
		Alg string `json:"alg"`
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(hb, &header) != nil || header.Alg != "HS256" {
		return "", errInvalid
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, h.sign(parts[0]+"."+parts[1])) {
		return "", errInvalid
	}
	var claims struct {
		Sub string `json:"sub"`
		Exp int64  `json:"exp"`
	}
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || json.Unmarshal(cb, &claims) != nil {
		return "", errInvalid
	}
	if claims.Sub == "" || claims.Exp == 0 || h.now().Unix() >= claims.Exp {
		return "", errInvalid
	}
	return claims.Sub, nil
}

// Mint issues a token for subject, for dev seeding and tests.
func (h HS256) Mint(subject string, ttl time.Duration) string {
	enc := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	input := enc(map[string]string{"alg": "HS256", "typ": "JWT"}) + "." +
		enc(map[string]any{"sub": subject, "exp": h.now().Add(ttl).Unix()})
	return fmt.Sprintf("%s.%s", input, base64.RawURLEncoding.EncodeToString(h.sign(input)))
}
