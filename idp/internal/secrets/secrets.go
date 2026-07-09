// Package secrets generates and hashes the high-entropy opaque tokens the idp
// hands out: authorization codes, refresh tokens, device codes, session IDs,
// client secrets.
//
// Storage rule: the plaintext value goes to the caller exactly once; only the
// SHA-256 hash is persisted. SHA-256 without salt or stretching is correct
// here — these are 256-bit random values, not human secrets, so dictionary
// and rainbow-table attacks don't apply and per-item salts add nothing.
package secrets

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// New returns a fresh 256-bit random token, base64url encoded, with an
// optional human-legible prefix ("rt_", "ac_", …) that aids log triage and
// secret scanning without adding guessability.
func New(prefix string) string {
	var buf [32]byte
	if _, err := rand.Read(buf[:]); err != nil {
		// crypto/rand failure is unrecoverable process-level breakage.
		panic("secrets: crypto/rand unavailable: " + err.Error())
	}
	return prefix + base64.RawURLEncoding.EncodeToString(buf[:])
}

// Hash returns the base64url SHA-256 of a token for storage/lookup.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// NewUserCode returns an RFC 8628 user code: 8 characters from a confusion-
// resistant alphabet (no 0/O/1/I/L), grouped as XXXX-XXXX for display.
func NewUserCode() (display, normalized string) {
	const alphabet = "BCDFGHJKMNPQRSTVWXYZ23456789"
	var buf [8]byte
	if _, err := rand.Read(buf[:]); err != nil {
		panic("secrets: crypto/rand unavailable: " + err.Error())
	}
	var sb strings.Builder
	for i, b := range buf {
		if i == 4 {
			sb.WriteByte('-')
		}
		sb.WriteByte(alphabet[int(b)%len(alphabet)])
	}
	display = sb.String()
	return display, NormalizeUserCode(display)
}

// NormalizeUserCode canonicalizes user input: uppercase, separators stripped.
func NormalizeUserCode(in string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z':
			return r - 32
		case r == '-' || r == ' ':
			return -1
		}
		return r
	}, in)
}
