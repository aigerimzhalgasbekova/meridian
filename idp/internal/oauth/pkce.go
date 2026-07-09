package oauth

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"regexp"
)

// PKCE (RFC 7636). Policy: S256 only. The "plain" method exists in the RFC
// for constrained clients but downgrades the proof to a bearer equivalent;
// rejecting it entirely is the RFC 9700 (OAuth Security BCP) recommendation.

// codeVerifierRe encodes RFC 7636 §4.1: 43–128 chars of [A-Za-z0-9-._~].
var codeVerifierRe = regexp.MustCompile(`^[A-Za-z0-9\-._~]{43,128}$`)

// ValidCodeChallenge reports whether ch is a plausible S256 challenge:
// base64url-no-pad of a SHA-256 digest is always exactly 43 characters.
func ValidCodeChallenge(ch string) bool {
	if len(ch) != 43 {
		return false
	}
	_, err := base64.RawURLEncoding.DecodeString(ch)
	return err == nil
}

// VerifyPKCE checks verifier against the stored S256 challenge in constant
// time. Empty challenge means the authorization was not PKCE-bound.
func VerifyPKCE(challenge, verifier string) bool {
	if challenge == "" || !codeVerifierRe.MatchString(verifier) {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}
