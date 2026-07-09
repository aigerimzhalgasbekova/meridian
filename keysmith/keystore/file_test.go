package keystore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/aikazzh/portfolio/keysmith/jose"
)

func testKEK(t *testing.T) *LocalKEK {
	t.Helper()
	master := make([]byte, 32)
	if _, err := rand.Read(master); err != nil {
		t.Fatal(err)
	}
	kek, err := NewLocalKEK("kek-test", master)
	if err != nil {
		t.Fatal(err)
	}
	return kek
}

func TestFileStorePersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "keys.json")
	kek := testKEK(t)

	s1, err := OpenFileStore(ctx, path, kek)
	if err != nil {
		t.Fatal(err)
	}
	k, err := newKey(jose.AlgEdDSA, 2048, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	k.State = StateActive
	if err := s1.Put(ctx, k); err != nil {
		t.Fatal(err)
	}

	// Reopen: key must round-trip through envelope encryption and sign.
	s2, err := OpenFileStore(ctx, path, kek)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s2.Get(ctx, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateActive || got.Alg != jose.AlgEdDSA {
		t.Fatalf("metadata lost: %+v", got)
	}
	token, err := jose.Sign([]byte(`{}`), got.SigningKey())
	if err != nil {
		t.Fatal(err)
	}
	set, err := jose.NewKeySet(got.VerificationKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := jose.Verify(token, set, []jose.Algorithm{jose.AlgEdDSA}); err != nil {
		t.Fatalf("reloaded key cannot sign/verify: %v", err)
	}
}

func TestFileStoreNoPlaintextKeyMaterialOnDisk(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "keys.json")
	s, err := OpenFileStore(ctx, path, testKEK(t))
	if err != nil {
		t.Fatal(err)
	}
	k, err := newKey(jose.AlgEdDSA, 2048, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, k); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// The Ed25519 seed must not appear anywhere in the file, in raw or
	// base64 form (JSON encodes []byte as std base64).
	seed := k.Private.(interface{ Seed() []byte }).Seed()
	if bytes.Contains(raw, seed) {
		t.Fatal("raw private key bytes on disk")
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err == nil && info.Mode().Perm() != 0o600 {
		t.Errorf("key file mode %v, want 0600", info.Mode().Perm())
	}
}

func TestFileStoreWrongKEKFailsClosed(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "keys.json")
	s, err := OpenFileStore(ctx, path, testKEK(t))
	if err != nil {
		t.Fatal(err)
	}
	k, err := newKey(jose.AlgES256, 2048, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, k); err != nil {
		t.Fatal(err)
	}

	t.Run("different KEK id", func(t *testing.T) {
		other := testKEK(t)
		if _, err := OpenFileStore(ctx, path, other); err == nil {
			t.Fatal("store opened with wrong KEK")
		}
	})

	t.Run("same id, different key material", func(t *testing.T) {
		master := make([]byte, 32)
		if _, err := rand.Read(master); err != nil {
			t.Fatal(err)
		}
		imposter, err := NewLocalKEK("kek-test", master)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileStore(ctx, path, imposter); err == nil {
			t.Fatal("store opened with imposter KEK")
		}
	})
}

func TestFileStoreTamperDetection(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "keys.json")
	kek := testKEK(t)
	s, err := OpenFileStore(ctx, path, kek)
	if err != nil {
		t.Fatal(err)
	}
	k1, err := newKey(jose.AlgEdDSA, 2048, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	k2, err := newKey(jose.AlgEdDSA, 2048, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, k1); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, k2); err != nil {
		t.Fatal(err)
	}

	// Swap the two records' encrypted blobs: the AAD (key ID) must catch it.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc fileDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Keys[0].PrivateCT, doc.Keys[1].PrivateCT = doc.Keys[1].PrivateCT, doc.Keys[0].PrivateCT
	doc.Keys[0].WrappedDEK, doc.Keys[1].WrappedDEK = doc.Keys[1].WrappedDEK, doc.Keys[0].WrappedDEK
	swapped, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, swapped, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(ctx, path, kek); err == nil {
		t.Fatal("record swap between key IDs went undetected")
	}
}

func TestLocalKEKValidation(t *testing.T) {
	if _, err := NewLocalKEK("id", make([]byte, 16)); err == nil {
		t.Error("16-byte master accepted")
	}
	if _, err := NewLocalKEK("", make([]byte, 32)); err == nil {
		t.Error("empty KEK id accepted")
	}
}

func TestManagerOnFileStore(t *testing.T) {
	// The full rotation lifecycle, persisted: restart mid-rotation and
	// continue where we left off.
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "keys.json")
	kek := testKEK(t)
	clock := newFakeClock()

	s1, err := OpenFileStore(ctx, path, kek)
	if err != nil {
		t.Fatal(err)
	}
	m1, err := NewManager(s1, testConfig(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	if err := m1.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	clock.Advance(24 * time.Hour)
	if err := m1.Tick(ctx); err != nil { // generates pending successor
		t.Fatal(err)
	}

	// "Restart": new store + manager over the same file and clock.
	s2, err := OpenFileStore(ctx, path, kek)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := NewManager(s2, testConfig(clock, nil))
	if err != nil {
		t.Fatal(err)
	}
	clock.Advance(10 * time.Minute)
	if err := m2.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	got := statesByAlg(t, m2, jose.AlgEdDSA)
	if got[StateActive] != 1 || got[StateRetiring] != 1 {
		t.Fatalf("rotation did not survive restart: %v", got)
	}
}

func TestErrorsAreComparable(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStore()
	if _, err := s.Get(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Error("Get miss should be ErrNotFound")
	}
	k, err := newKey(jose.AlgEdDSA, 2048, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, k); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, k); !errors.Is(err, ErrDuplicate) {
		t.Error("duplicate Put should be ErrDuplicate")
	}
}
