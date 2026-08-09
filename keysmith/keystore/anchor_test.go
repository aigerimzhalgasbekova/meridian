package keystore

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aikazzh/portfolio/keysmith/jose"
)

// memAnchor stands in for the SSM parameter: generation held outside the
// keystore file, beyond the file-write attacker's reach. Mutex because anchor
// advances run in goroutines.
type memAnchor struct {
	mu     sync.Mutex
	gen    int
	getErr error
	setErr error
}

func (a *memAnchor) Get(context.Context) (int, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.gen, a.getErr
}

func (a *memAnchor) Set(_ context.Context, gen int) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.setErr != nil {
		return a.setErr
	}
	a.gen = gen
	return nil
}

func (a *memAnchor) fail(get, set error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.getErr, a.setErr = get, set
}

func (a *memAnchor) generation() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.gen
}

func (a *memAnchor) setGen(gen int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.gen = gen
}

func TestGenerationAnchor(t *testing.T) {
	ctx := context.Background()
	newStoreWithKey := func(t *testing.T, anchor Anchor) (path string, kek *LocalKEK) {
		t.Helper()
		path = filepath.Join(t.TempDir(), "keys.json")
		kek = testKEK(t)
		s, err := OpenFileStore(ctx, path, kek, anchor)
		if err != nil {
			t.Fatal(err)
		}
		k, err := newKey(jose.AlgEdDSA, 2048, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		k.State = StateActive
		if err := s.Put(ctx, k); err != nil {
			t.Fatal(err)
		}
		if err := s.Close(); err != nil { // waits for the async anchor advance
			t.Fatal(err)
		}
		return path, kek
	}

	t.Run("advances on persist and accepts the current file", func(t *testing.T) {
		anchor := &memAnchor{}
		path, kek := newStoreWithKey(t, anchor)
		if g := anchor.generation(); g != 1 {
			t.Fatalf("anchor after first Put = %d, want 1", g)
		}
		s, err := OpenFileStore(ctx, path, kek, anchor)
		if err != nil {
			t.Fatalf("reopening the untampered store: %v", err)
		}
		s.Close()
	})

	t.Run("refuses a rolled-back file", func(t *testing.T) {
		anchor := &memAnchor{}
		path, kek := newStoreWithKey(t, anchor)
		old, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		s, err := OpenFileStore(ctx, path, kek, anchor)
		if err != nil {
			t.Fatal(err)
		}
		k2, err := newKey(jose.AlgEdDSA, 2048, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, k2); err != nil {
			t.Fatal(err)
		}
		s.Close()
		// The attacker restores the pre-rotation copy: internally consistent,
		// verifies under its own generation, and only the anchor knows better.
		if err := os.WriteFile(path, old, 0o600); err != nil {
			t.Fatal(err)
		}
		if s, err := OpenFileStore(ctx, path, kek, anchor); err == nil {
			s.Close()
			t.Fatal("rolled-back keystore opened; the anchor did not detect it")
		} else if !strings.Contains(err.Error(), "rollback") {
			t.Fatalf("want a rollback error, got: %v", err)
		}
	})

	t.Run("refuses a deleted file when the anchor records writes", func(t *testing.T) {
		anchor := &memAnchor{}
		path, kek := newStoreWithKey(t, anchor)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if s, err := OpenFileStore(ctx, path, kek, anchor); err == nil {
			s.Close()
			t.Fatal("store initialized fresh over a deleted keystore the anchor knew about")
		}
	})

	t.Run("refuses a v1 document when the anchor records writes", func(t *testing.T) {
		anchor := &memAnchor{}
		path, kek := newStoreWithKey(t, anchor)
		// A retained pre-upgrade v1 copy with the plaintext generation bumped
		// past the anchor: the v1 AAD does not bind the generation, so the
		// numeric comparison alone would wave it through.
		k, err := newKey(jose.AlgEdDSA, 2048, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		k.State = StateActive
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
		writeDoc(t, path, fileDoc{Version: 1, Generation: 999, Keys: []fileRecord{{
			ID: k.ID, Alg: string(k.Alg), State: string(k.State), CreatedAt: k.CreatedAt,
			KEKID: kek.ID(), WrappedDEK: wrapped, PrivateCT: ct, PublicJWK: pubJWK,
		}}})
		if s, err := OpenFileStore(ctx, path, kek, anchor); err == nil {
			s.Close()
			t.Fatal("v1 document with a forged generation opened under a non-zero anchor")
		} else if !strings.Contains(err.Error(), "rollback") {
			t.Fatalf("want a rollback error, got: %v", err)
		}
	})

	t.Run("anchor write failure does not fail the write and never leads the file", func(t *testing.T) {
		anchor := &memAnchor{}
		path, kek := newStoreWithKey(t, anchor)
		s, err := OpenFileStore(ctx, path, kek, anchor)
		if err != nil {
			t.Fatal(err)
		}
		anchor.fail(nil, errors.New("ssm unavailable"))
		k2, err := newKey(jose.AlgEdDSA, 2048, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, k2); err != nil {
			t.Fatalf("Put failed for an anchor outage although the document was already durable: %v", err)
		}
		s.Close()
		// Anchor behind the file is the safe failure mode: it must not have
		// advanced, and the store on disk (generation 2) must still open against
		// the stale anchor (generation 1) — with the key written during the
		// outage present, so memory never diverged from disk.
		if g := anchor.generation(); g != 1 {
			t.Fatalf("anchor = %d after a failed Set, want the stale 1", g)
		}
		anchor.fail(nil, nil)
		s2, err := OpenFileStore(ctx, path, kek, anchor)
		if err != nil {
			t.Fatalf("file ahead of anchor must open: %v", err)
		}
		if _, err := s2.Get(ctx, k2.ID); err != nil {
			t.Fatalf("key written during the anchor outage is missing after reopen: %v", err)
		}
		s2.Close()
	})

	t.Run("anchor unreadable: intact store opens degraded and re-anchors on the next write", func(t *testing.T) {
		anchor := &memAnchor{}
		path, kek := newStoreWithKey(t, anchor)
		anchor.fail(errors.New("ssm unavailable"), nil)
		s, err := OpenFileStore(ctx, path, kek, anchor)
		if err != nil {
			t.Fatalf("intact store must open when the anchor is unreadable: %v", err)
		}
		anchor.fail(nil, nil) // outage ends before the next write
		k2, err := newKey(jose.AlgEdDSA, 2048, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, k2); err != nil {
			t.Fatal(err)
		}
		s.Close()
		if g := anchor.generation(); g != 2 {
			t.Fatalf("anchor = %d after the post-outage write, want 2", g)
		}
	})

	t.Run("anchor unreadable: refuses to initialize a fresh store", func(t *testing.T) {
		anchor := &memAnchor{}
		anchor.fail(errors.New("ssm unavailable"), nil)
		path := filepath.Join(t.TempDir(), "keys.json")
		if s, err := OpenFileStore(ctx, path, testKEK(t), anchor); err == nil {
			s.Close()
			t.Fatal("fresh store initialized while the anchor was unreadable: a wipe would look identical")
		}
	})

	t.Run("degraded open never lowers a higher anchor", func(t *testing.T) {
		anchor := &memAnchor{}
		path, kek := newStoreWithKey(t, anchor)
		// The file at generation 1 is a rollback the open cannot see: the real
		// anchor records 5 writes but is unreadable at open time.
		anchor.setGen(5)
		anchor.fail(errors.New("ssm unavailable"), nil)
		s, err := OpenFileStore(ctx, path, kek, anchor)
		if err != nil {
			t.Fatal(err)
		}
		anchor.fail(nil, nil)
		k2, err := newKey(jose.AlgEdDSA, 2048, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, k2); err != nil { // persists generation 2
			t.Fatal(err)
		}
		s.Close()
		if g := anchor.generation(); g != 5 {
			t.Fatalf("degraded store lowered the anchor to %d, destroying the rollback evidence", g)
		}
	})
}
