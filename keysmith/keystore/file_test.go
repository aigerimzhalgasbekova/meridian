package keystore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
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
	// Deliberately a local wall clock with a monotonic reading, as the daemon
	// uses: the timestamps are inside the AEAD now, so encode and decode must
	// agree on their canonical form across the JSON round trip and the zone.
	k, err := newKey(jose.AlgEdDSA, 2048, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	k.State = StateActive
	if err := s1.Put(ctx, k); err != nil {
		t.Fatal(err)
	}
	// The store holds an exclusive lock for its lifetime; a reopen in the same
	// process is a second writer just like a second process.
	if err := s1.Close(); err != nil {
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
	if err := s.Close(); err != nil {
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
	if err := s.Close(); err != nil {
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

func TestFileStorePublicKeyTamperRejected(t *testing.T) {
	// KS-P0: the published public key must be derived from the encrypted
	// private key, not trusted from the plaintext public_jwk field. Swapping in
	// an attacker's public key under a legitimate kid must fail closed.
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "keys.json")
	kek := testKEK(t)
	s, err := OpenFileStore(ctx, path, kek)
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
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	// Attacker overwrites public_jwk with a key they hold the private half of,
	// leaving the kid and encrypted private material untouched.
	attacker, err := newKey(jose.AlgEdDSA, 2048, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	evilJWK, err := jose.PublicJWK(attacker.VerificationKey())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc fileDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc.Keys[0].PublicJWK = evilJWK
	tampered, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	// public_jwk is not the source of truth: it is ignored and the public key
	// is re-derived from the encrypted private material, so the attacker's key
	// never gets published under the legitimate kid.
	s2, err := OpenFileStore(ctx, path, kek)
	if err != nil {
		t.Fatalf("reopen after public_jwk swap: %v", err)
	}
	got, err := s2.Get(ctx, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Public.(ed25519.PublicKey).Equal(k.Public.(ed25519.PublicKey)) {
		t.Fatal("attacker public_jwk was published under legitimate kid: forgery possible")
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}

	// A kid that does not match the thumbprint of the private key is rejected.
	doc.Keys[0].ID = "sha256:not-the-real-thumbprint"
	badKid, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, badKid, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileStore(ctx, path, kek); err == nil {
		t.Fatal("kid/thumbprint mismatch went undetected")
	}
}

func readDoc(t *testing.T, path string) fileDoc {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc fileDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func writeDoc(t *testing.T, path string, doc fileDoc) {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestFileStoreLifecycleTamperRejected is KS-P0's other half: the thumbprint
// check proves the key *material* is genuine but says nothing about its
// lifecycle *position*. With state and timestamps outside the AEAD, an
// attacker with file write access and no KEK could flip a retired key back to
// active — resurrecting a key whose private half they stole — or backdate
// created_at to walk straight through the pending dwell.
func TestFileStoreLifecycleTamperRejected(t *testing.T) {
	ctx := context.Background()
	kek := testKEK(t)
	now := time.Now().UTC()

	mutations := []struct {
		name string
		edit func(*fileRecord)
	}{
		{"state retired → active", func(r *fileRecord) { r.State = string(StateActive) }},
		{"created_at backdated", func(r *fileRecord) { r.CreatedAt = r.CreatedAt.Add(-48 * time.Hour) }},
		{"promoted_at forward-dated", func(r *fileRecord) { r.PromotedAt = now.Add(48 * time.Hour) }},
		{"retiring_at zeroed", func(r *fileRecord) { r.RetiringAt = time.Time{} }},
		{"retired_at zeroed", func(r *fileRecord) { r.RetiredAt = time.Time{} }},
	}
	for _, tc := range mutations {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "keys.json")
			s, err := OpenFileStore(ctx, path, kek)
			if err != nil {
				t.Fatal(err)
			}
			k, err := newKey(jose.AlgEdDSA, 2048, now)
			if err != nil {
				t.Fatal(err)
			}
			k.State, k.PromotedAt, k.RetiringAt, k.RetiredAt = StateRetired, now, now, now
			if err := s.Put(ctx, k); err != nil {
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}

			doc := readDoc(t, path)
			tc.edit(&doc.Keys[0])
			writeDoc(t, path, doc)

			s2, err := OpenFileStore(ctx, path, kek)
			if err == nil {
				s2.Close()
				t.Fatal("lifecycle metadata edited in plaintext went undetected")
			}
		})
	}
}

// TestFileStoreRecordReplayRejected: binding the lifecycle into each record's
// AAD is not enough on its own. Every record is sealed independently, so an
// authentic record kept from while the key was active can be spliced over its
// retired successor — a resurrection with no KEK and no forged bytes. The
// document generation in the AAD is what stops records from different writes
// being mixed.
func TestFileStoreRecordReplayRejected(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "keys.json")
	kek := testKEK(t)
	now := time.Now().UTC()

	s, err := OpenFileStore(ctx, path, kek)
	if err != nil {
		t.Fatal(err)
	}
	k1, err := newKey(jose.AlgEdDSA, 2048, now)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := newKey(jose.AlgEdDSA, 2048, now)
	if err != nil {
		t.Fatal(err)
	}
	k1.State, k1.PromotedAt = StateActive, now
	if err := s.Put(ctx, k1); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, k2); err != nil {
		t.Fatal(err)
	}
	// The attacker's snapshot of the file, taken while k1 was still active.
	snapshot := readDoc(t, path)

	k1.State, k1.RetiringAt, k1.RetiredAt = StateRetired, now, now
	if err := s.Update(ctx, k1); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		gen  int // document generation the attacker claims
	}{
		{"record from an earlier generation", 0},
		{"generation rolled back with it", snapshot.Generation},
	} {
		t.Run(tc.name, func(t *testing.T) {
			doc := readDoc(t, path)
			doc.Keys[0] = snapshot.Keys[0] // verbatim, exactly as keysmith sealed it
			if tc.gen != 0 {
				doc.Generation = tc.gen
			}
			writeDoc(t, path, doc)

			s2, err := OpenFileStore(ctx, path, kek)
			if err == nil {
				got, _ := s2.Get(ctx, k1.ID)
				s2.Close()
				t.Fatalf("record replay resurrected a retired key as %q", got.State)
			}
		})
	}
}

// TestFileStoreV1LoadsAndUpgrades pins the migration: an existing v1 keystore
// must still open (bricking a live deployment is worse than the hole) and must
// be rewritten at v2 so the old, forgeable form does not survive a restart —
// but only as a deliberate operator action. A v1 document accepted by default
// would be a permanent lifecycle-forgery primitive: its state and timestamps
// are unauthenticated, and the upgrade would launder the forged lifecycle into
// a valid v2 record.
func TestFileStoreV1LoadsAndUpgrades(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "keys.json")
	kek := testKEK(t)
	now := time.Now().UTC()

	k, err := newKey(jose.AlgEdDSA, 2048, now)
	if err != nil {
		t.Fatal(err)
	}
	k.State, k.PromotedAt = StateActive, now
	pkcs8, err := x509.MarshalPKCS8PrivateKey(k.Private)
	if err != nil {
		t.Fatal(err)
	}
	ct, wrapped, err := envelopeSeal(ctx, kek, pkcs8, aad(k.ID, k.Alg)) // v1 AAD
	if err != nil {
		t.Fatal(err)
	}
	pubJWK, err := jose.PublicJWK(k.VerificationKey())
	if err != nil {
		t.Fatal(err)
	}
	writeDoc(t, path, fileDoc{Version: 1, Keys: []fileRecord{{
		ID: k.ID, Alg: string(k.Alg), State: string(k.State),
		CreatedAt: k.CreatedAt, PromotedAt: k.PromotedAt,
		KEKID: kek.ID(), WrappedDEK: wrapped, PrivateCT: ct, PublicJWK: pubJWK,
	}}})

	// Without the opt-in the downgrade path is closed, so a retained copy of a
	// pre-upgrade file is not a standing forgery primitive.
	if s, err := OpenFileStore(ctx, path, kek); err == nil {
		s.Close()
		t.Fatalf("v1 document accepted without %s", migrateEnvVar)
	}

	t.Setenv(migrateEnvVar, "1")
	s, err := OpenFileStore(ctx, path, kek)
	if err != nil {
		t.Fatalf("v1 keystore no longer opens under the migration opt-in — this bricks live deployments: %v", err)
	}
	got, err := s.Get(ctx, k.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != StateActive || !got.PromotedAt.Equal(k.PromotedAt) {
		t.Fatalf("v1 metadata lost on upgrade: %+v", got)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	if v := readDoc(t, path).Version; v != fileVersion {
		t.Fatalf("document left at version %d, want %d", v, fileVersion)
	}
	// And now the lifecycle fields are authenticated.
	doc := readDoc(t, path)
	doc.Keys[0].State = string(StateRetired)
	writeDoc(t, path, doc)
	if s2, err := OpenFileStore(ctx, path, kek); err == nil {
		s2.Close()
		t.Fatal("state edit accepted after the v2 upgrade")
	}
}

// TestOpenFileStoreWarnsWhenMigrationOptInLeftSet: the migration opt-in has to
// be set in the serving task's environment for the deploy that upgrades the
// deployed v1 keystore, and dropped in the next one. Nothing forces the second
// deploy, and refusing to start would swap the downgrade window for an outage of
// the platform's only signer — so a store that is already at the current version
// must at least say so on every start.
func TestOpenFileStoreWarnsWhenMigrationOptInLeftSet(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "keys.json")
	kek := testKEK(t)
	s, err := OpenFileStore(ctx, path, kek)
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
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	var logged bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	t.Setenv(migrateEnvVar, "1")
	s2, err := OpenFileStore(ctx, path, kek)
	if err != nil {
		t.Fatalf("a current-version store must still open with the opt-in set: %v", err)
	}
	if err := s2.Close(); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(logged.Bytes(), []byte(migrateEnvVar)) {
		t.Fatalf("%s left set on an already-v%d store logged nothing: %q", migrateEnvVar, fileVersion, logged.String())
	}
}

// TestPersistDoesNotReuseAGenerationAfterDirSyncFailure: persist renames the new
// document into place and only then fsyncs the directory. If that fsync fails,
// the write is reported as an error and Put/Update roll their in-memory mutation
// back — but the document carrying generation `next` is already on disk. Leaving
// the counter behind seals the next, *different* record set under that same
// generation, and two documents sharing a generation re-open the record splice
// the generation was added to prevent.
func TestPersistDoesNotReuseAGenerationAfterDirSyncFailure(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions, so the fsync cannot be made to fail")
	}
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "keys.json")
	kek := testKEK(t)
	s, err := OpenFileStore(ctx, path, kek)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	mkKey := func() Key {
		t.Helper()
		k, err := newKey(jose.AlgEdDSA, 2048, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	if err := s.Put(ctx, mkKey()); err != nil {
		t.Fatal(err)
	}

	// Write and execute but not read: CreateTemp and Rename still work,
	// os.Open(dir) for the fsync does not.
	if err := os.Chmod(dir, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })
	if err := s.Put(ctx, mkKey()); err == nil {
		t.Fatal("directory fsync failure was not reported to the caller")
	}
	orphan := readDoc(t, path).Generation
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := s.Put(ctx, mkKey()); err != nil {
		t.Fatal(err)
	}
	if got := readDoc(t, path).Generation; got == orphan {
		t.Fatalf("generation %d reused: the orphaned document and the live one carry the same generation, "+
			"so a record from one splices into the other with a matching AAD", got)
	}
}

func TestOpenFileStoreRejectsCorruptDocuments(t *testing.T) {
	ctx := context.Background()
	kek := testKEK(t)

	newStore := func(t *testing.T) (string, fileDoc) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "keys.json")
		s, err := OpenFileStore(ctx, path, kek)
		if err != nil {
			t.Fatal(err)
		}
		k, err := newKey(jose.AlgEdDSA, 2048, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		k.State = StateActive
		if err := s.Put(ctx, k); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		return path, readDoc(t, path)
	}

	t.Run("duplicate record", func(t *testing.T) {
		// A duplicated record yields a one-entry map with a two-entry order,
		// so List returns the key twice and every VerificationSet call fails
		// on a duplicate kid — permanently, and across restarts.
		path, doc := newStore(t)
		doc.Keys = append(doc.Keys, doc.Keys[0])
		writeDoc(t, path, doc)
		s, err := OpenFileStore(ctx, path, kek)
		if err == nil {
			s.Close()
			t.Fatal("duplicate key record accepted")
		}
		if !errors.Is(err, ErrDuplicate) {
			t.Errorf("want ErrDuplicate, got %v", err)
		}
	})

	t.Run("unknown document version", func(t *testing.T) {
		path, doc := newStore(t)
		doc.Version = fileVersion + 1
		writeDoc(t, path, doc)
		s, err := OpenFileStore(ctx, path, kek)
		if err == nil {
			s.Close()
			t.Fatal("future document version accepted")
		}
	})
}

func TestFileStoreRefusesASecondWriter(t *testing.T) {
	// Two writers against one file is silent key loss: each persist() replays
	// that process's whole in-memory snapshot over the other's writes.
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "keys.json")
	kek := testKEK(t)
	s1, err := OpenFileStore(ctx, path, kek)
	if err != nil {
		t.Fatal(err)
	}
	defer s1.Close()
	if s2, err := OpenFileStore(ctx, path, kek); err == nil {
		s2.Close()
		t.Fatal("a second writer opened the same keystore")
	}
	// Released on Close, so a restart is not locked out by its own predecessor.
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}
	s3, err := OpenFileStore(ctx, path, kek)
	if err != nil {
		t.Fatalf("lock not released on Close: %v", err)
	}
	s3.Close()
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
	if err := s1.Close(); err != nil {
		t.Fatal(err)
	}
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
