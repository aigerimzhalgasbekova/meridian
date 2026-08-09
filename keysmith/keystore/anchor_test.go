package keystore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/aikazzh/portfolio/keysmith/jose"
)

// memAnchor stands in for the SSM parameter: generation held outside the
// keystore file, beyond the file-write attacker's reach.
type memAnchor struct {
	gen int
	set bool
	err error // returned from both Get and Set when non-nil
}

func (a *memAnchor) Get(context.Context) (int, bool, error) { return a.gen, a.set, a.err }
func (a *memAnchor) Set(_ context.Context, gen int) error {
	if a.err != nil {
		return a.err
	}
	a.gen, a.set = gen, true
	return nil
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
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		return path, kek
	}

	t.Run("advances on persist and accepts the current file", func(t *testing.T) {
		anchor := &memAnchor{}
		path, kek := newStoreWithKey(t, anchor)
		if !anchor.set || anchor.gen != 1 {
			t.Fatalf("anchor after first Put = (%d, %v), want (1, true)", anchor.gen, anchor.set)
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

	t.Run("failed anchor write surfaces and never leads the file", func(t *testing.T) {
		anchor := &memAnchor{}
		path, kek := newStoreWithKey(t, anchor)
		s, err := OpenFileStore(ctx, path, kek, anchor)
		if err != nil {
			t.Fatal(err)
		}
		anchor.err = errors.New("ssm unavailable")
		k2, err := newKey(jose.AlgEdDSA, 2048, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if err := s.Put(ctx, k2); err == nil {
			t.Fatal("Put succeeded although the anchor could not advance")
		}
		s.Close()
		// Anchor behind the file is the safe failure mode: the store on disk
		// (generation 2) must still open against the stale anchor (generation 1).
		anchor.err = nil
		s2, err := OpenFileStore(ctx, path, kek, anchor)
		if err != nil {
			t.Fatalf("file ahead of anchor must open: %v", err)
		}
		s2.Close()
	})
}
