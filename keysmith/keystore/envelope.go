package keystore

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// KEK wraps and unwraps data-encryption keys. The envelope scheme: each stored
// private key is encrypted with its own random 256-bit DEK (AES-256-GCM), and
// only the DEK is wrapped by the KEK. Swapping the KEK (e.g. local secret →
// AWS KMS) or rotating it never requires re-encrypting key material at scale —
// only re-wrapping DEKs.
type KEK interface {
	// ID identifies the KEK so stored records can name the wrapper that
	// protects them (supports KEK rotation and mixed-KEK stores).
	ID() string
	Wrap(ctx context.Context, dek []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrapped []byte) ([]byte, error)
}

// ErrKEKMismatch is returned when a record was wrapped by a different KEK.
var ErrKEKMismatch = errors.New("keystore: record wrapped by a different KEK")

// LocalKEK is an AES-256-GCM key-encryption key held in process memory,
// sourced from configuration (env var / mounted secret). Suitable for dev and
// single-node deployments; production deployments should use a cloud KMS
// implementation of the KEK interface so the master key never exists in
// application memory.
type LocalKEK struct {
	id   string
	aead cipher.AEAD
}

// NewLocalKEK builds a LocalKEK from a 32-byte master key.
func NewLocalKEK(id string, master []byte) (*LocalKEK, error) {
	if len(master) != 32 {
		return nil, fmt.Errorf("keystore: master key must be 32 bytes, got %d", len(master))
	}
	if id == "" {
		return nil, errors.New("keystore: KEK id required")
	}
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &LocalKEK{id: id, aead: aead}, nil
}

func (k *LocalKEK) ID() string { return k.id }

func (k *LocalKEK) Wrap(_ context.Context, dek []byte) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// KEK ID as AAD binds the wrapped DEK to this wrapper.
	return k.aead.Seal(nonce, nonce, dek, []byte(k.id)), nil
}

func (k *LocalKEK) Unwrap(_ context.Context, wrapped []byte) ([]byte, error) {
	if len(wrapped) < k.aead.NonceSize() {
		return nil, errors.New("keystore: wrapped DEK too short")
	}
	nonce, ct := wrapped[:k.aead.NonceSize()], wrapped[k.aead.NonceSize():]
	dek, err := k.aead.Open(nil, nonce, ct, []byte(k.id))
	if err != nil {
		return nil, fmt.Errorf("keystore: unwrap DEK: %w", err)
	}
	return dek, nil
}

// envelope seals plaintext under a fresh DEK and returns (ciphertext,
// wrappedDEK). AAD binds the ciphertext to the key's identity so records
// cannot be swapped between key IDs.
func envelopeSeal(ctx context.Context, kek KEK, plaintext, aad []byte) (ct, wrappedDEK []byte, err error) {
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, err
	}
	ct = aead.Seal(nonce, nonce, plaintext, aad)
	wrappedDEK, err = kek.Wrap(ctx, dek)
	if err != nil {
		return nil, nil, err
	}
	return ct, wrappedDEK, nil
}

func envelopeOpen(ctx context.Context, kek KEK, ct, wrappedDEK, aad []byte) ([]byte, error) {
	dek, err := kek.Unwrap(ctx, wrappedDEK)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ct) < aead.NonceSize() {
		return nil, errors.New("keystore: ciphertext too short")
	}
	nonce, body := ct[:aead.NonceSize()], ct[aead.NonceSize():]
	pt, err := aead.Open(nil, nonce, body, aad)
	if err != nil {
		return nil, fmt.Errorf("keystore: open envelope: %w", err)
	}
	return pt, nil
}
