// Package password implements Argon2id password hashing with the OWASP
// recommended parameter set and constant-time verification.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Params are Argon2id cost parameters. Defaults follow the OWASP Password
// Storage Cheat Sheet first-choice configuration: m=19 MiB, t=2, p=1.
type Params struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	SaltLen     uint32
	KeyLen      uint32
}

// Default is the production parameter set.
var Default = Params{
	MemoryKiB:   19 * 1024,
	Iterations:  2,
	Parallelism: 1,
	SaltLen:     16,
	KeyLen:      32,
}

// Hash derives an encoded Argon2id hash:
// $argon2id$v=19$m=...,t=...,p=...$<salt-b64>$<key-b64>
func Hash(plaintext string, p Params) (string, error) {
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(plaintext), salt, p.Iterations, p.MemoryKiB, p.Parallelism, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.MemoryKiB, p.Iterations, p.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key)), nil
}

// ErrMalformedHash means the encoded hash could not be parsed.
var ErrMalformedHash = errors.New("password: malformed encoded hash")

// Verify checks plaintext against an encoded hash in constant time (with
// respect to the derived key comparison). It returns (false, nil) on
// mismatch and reserves errors for malformed inputs.
func Verify(plaintext, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return false, ErrMalformedHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return false, ErrMalformedHash
	}
	var p Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.MemoryKiB, &p.Iterations, &p.Parallelism); err != nil {
		return false, ErrMalformedHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrMalformedHash
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrMalformedHash
	}
	got := argon2.IDKey([]byte(plaintext), salt, p.Iterations, p.MemoryKiB, p.Parallelism, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// NeedsRehash reports whether the encoded hash uses weaker parameters than p
// (login paths call this to transparently upgrade hashes over time). Weaker
// means any dimension: cost (m/t/p), salt length, key length, or an outdated
// argon2 version — Verify accepts all of these, so this is the only place
// they get caught.
func NeedsRehash(encoded string, p Params) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return true
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return true
	}
	var cur Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &cur.MemoryKiB, &cur.Iterations, &cur.Parallelism); err != nil {
		return true
	}
	salt, err1 := base64.RawStdEncoding.DecodeString(parts[4])
	key, err2 := base64.RawStdEncoding.DecodeString(parts[5])
	if err1 != nil || err2 != nil {
		return true
	}
	return cur.MemoryKiB < p.MemoryKiB || cur.Iterations < p.Iterations || cur.Parallelism < p.Parallelism ||
		uint32(len(salt)) < p.SaltLen || uint32(len(key)) < p.KeyLen
}
