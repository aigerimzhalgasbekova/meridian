package keystore

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/aikazzh/portfolio/keysmith/jose"
)

// fileVersion is the document format this store writes. v1 bound only the key
// ID and algorithm into the AEAD; v2 additionally binds the lifecycle state,
// the timestamps and the document generation.
//
// A v1 document loads — verified under the v1 AAD — and is rewritten at v2 on
// open: back-compat on read, upgrade on write, no env var and no operator step.
// The residual downgrade path — a KEK-less attacker replaying a *retained*
// pre-upgrade copy whose lifecycle fields are unauthenticated — is closed by
// the generation Anchor when one is configured: the retained copy necessarily
// carries a generation below the anchored one and is refused on open. An
// operator-set opt-in did not close it, it only converted the exposure into a
// way to brick the platform's only signer on deploy. Documented in
// THREAT_MODEL.md.
const fileVersion = 2

// FileStore persists keys to a single JSON file with private key material
// envelope-encrypted. Writes are atomic (temp file + rename) and fsynced.
// Single-writer by construction: an advisory lock is held for the store's
// lifetime, so a second process fails to start rather than silently replaying
// its stale whole-document snapshot over the first one's writes.
type FileStore struct {
	path   string
	kek    KEK
	anchor Anchor // nil disables rollback detection (dev / no external store)
	lock   *os.File

	mu    sync.RWMutex
	keys  map[string]Key
	order []string
	gen   int // document generation of the last successful persist
}

type fileRecord struct {
	ID         string    `json:"id"`
	Alg        string    `json:"alg"`
	State      string    `json:"state"`
	CreatedAt  time.Time `json:"created_at"`
	PromotedAt time.Time `json:"promoted_at,omitzero"`
	RetiringAt time.Time `json:"retiring_at,omitzero"`
	RetiredAt  time.Time `json:"retired_at,omitzero"`

	KEKID      string   `json:"kek_id"`
	WrappedDEK []byte   `json:"wrapped_dek"`
	PrivateCT  []byte   `json:"private_ct"` // AES-256-GCM over PKCS#8
	PublicJWK  jose.JWK `json:"public_jwk"`
}

type fileDoc struct {
	Version int `json:"version"`
	// Generation increments on every persist and is bound into each record's
	// AAD, so a record sealed by an earlier write cannot be spliced into a later
	// document. Without it every record verifies on its own merits forever, and
	// an attacker who kept the record for key K from while K was active can
	// paste it over K's retired successor with no KEK.
	//
	// The counter travels with the file, so on its own a whole-file rollback
	// still passes; a configured Anchor (see anchor.go) holds the current
	// generation outside the keystore and OpenFileStore refuses any document
	// below it.
	Generation int          `json:"generation"`
	Keys       []fileRecord `json:"keys"`
}

// OpenFileStore loads (or initializes) the store at path. The returned store
// holds an exclusive advisory lock until Close.
//
// A non-nil anchor closes the whole-file rollback hole: opening fails if the
// document's generation is below the anchored one, or if the file is missing
// while the anchor says writes happened. Both failures mean the keystore an
// attacker (or a bad restore) put in place is older than the one last written
// — refusing to start is the detection this store otherwise cannot provide.
// nil skips the check and matches the pre-anchor behavior.
func OpenFileStore(ctx context.Context, path string, kek KEK, anchor Anchor) (*FileStore, error) {
	s := &FileStore{path: path, kek: kek, anchor: anchor, keys: make(map[string]Key)}
	// The lock lives beside the keystore rather than on it: persist() renames a
	// new file over the path, so a lock held on the keystore's own descriptor
	// would guard an unlinked inode while a second process locked the new one.
	// ponytail: flock is advisory and unix-only, which suits this deployment;
	// a database store with a rotation leader is the multi-node upgrade path.
	lockPath := path + ".lock"
	lock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("keystore: open lock %s: %w", lockPath, err)
	}
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, fmt.Errorf("keystore: another keysmith holds the keystore %s: %w", path, err)
	}
	s.lock = lock

	anchored := 0
	if anchor != nil {
		gen, ok, err := anchor.Get(ctx)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("keystore: read generation anchor: %w", err)
		}
		if ok {
			anchored = gen
		}
	}

	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		if anchored > 0 {
			s.Close()
			return nil, fmt.Errorf("keystore: %s is missing but the generation anchor records %d writes: refusing to initialize a fresh store over a rolled-back one",
				path, anchored)
		}
		return s, nil
	}
	if err != nil {
		s.Close()
		return nil, fmt.Errorf("keystore: read %s: %w", path, err)
	}
	var doc fileDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		s.Close()
		return nil, fmt.Errorf("keystore: parse %s: %w", path, err)
	}
	if doc.Version < 1 || doc.Version > fileVersion {
		s.Close()
		return nil, fmt.Errorf("keystore: %s has document version %d, this build understands 1..%d",
			path, doc.Version, fileVersion)
	}
	if doc.Generation < anchored {
		s.Close()
		return nil, fmt.Errorf("keystore: %s carries generation %d but the anchor records %d: whole-file rollback detected, refusing to open",
			path, doc.Generation, anchored)
	}
	s.gen = doc.Generation
	for _, rec := range doc.Keys {
		k, err := s.decode(ctx, rec, doc.Version, doc.Generation)
		if err != nil {
			s.Close()
			return nil, fmt.Errorf("keystore: key %q: %w", rec.ID, err)
		}
		// Put guards duplicates on write; the load path must establish the same
		// len(order) == len(keys) invariant, or List returns the key twice and
		// every VerificationSet call fails on a duplicate kid, permanently.
		if _, dup := s.keys[k.ID]; dup {
			s.Close()
			return nil, fmt.Errorf("keystore: duplicate key %q in %s: %w", k.ID, path, ErrDuplicate)
		}
		s.keys[k.ID] = k
		s.order = append(s.order, k.ID)
	}
	if doc.Version < fileVersion && len(s.order) > 0 {
		// Rewrite once at the current version so the lifecycle metadata comes
		// under the AEAD; after this the old, forgeable form is gone.
		if err := s.persist(ctx); err != nil {
			s.Close()
			return nil, fmt.Errorf("keystore: upgrade %s to v%d: %w", path, fileVersion, err)
		}
	}
	return s, nil
}

// Close releases the keystore lock.
func (s *FileStore) Close() error {
	if s.lock == nil {
		return nil
	}
	err := s.lock.Close() // releases the flock with the descriptor
	s.lock = nil
	return err
}

// aad binds a record's ciphertext to its identity. v1 covered only the key ID
// and algorithm, leaving state and timestamps as unauthenticated plaintext: a
// file-write attacker with no KEK could flip a retired key back to active and
// resurrect it as the signer, or backdate created_at past the pending dwell.
func aad(id string, alg jose.Algorithm) []byte {
	return []byte("keysmith:key:" + id + ":" + string(alg))
}

// aadV2 additionally binds the lifecycle position and the document generation
// the record was written in, so editing any of it — or replaying an authentic
// record from an earlier generation — turns the record into an AEAD failure
// instead of a silent state change.
func aadV2(rec fileRecord, gen int) []byte {
	ts := func(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }
	return []byte("keysmith:key:v2:" + rec.ID + ":" + rec.Alg + ":" + rec.State + ":" +
		ts(rec.CreatedAt) + ":" + ts(rec.PromotedAt) + ":" + ts(rec.RetiringAt) + ":" + ts(rec.RetiredAt) +
		":gen:" + strconv.Itoa(gen))
}

func (s *FileStore) encode(ctx context.Context, k Key, gen int) (fileRecord, error) {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(k.Private)
	if err != nil {
		return fileRecord{}, fmt.Errorf("marshal private key: %w", err)
	}
	rec := fileRecord{
		ID: k.ID, Alg: string(k.Alg), State: string(k.State),
		CreatedAt: k.CreatedAt, PromotedAt: k.PromotedAt,
		RetiringAt: k.RetiringAt, RetiredAt: k.RetiredAt,
	}
	ct, wrapped, err := envelopeSeal(ctx, s.kek, pkcs8, aadV2(rec, gen))
	if err != nil {
		return fileRecord{}, err
	}
	pubJWK, err := jose.PublicJWK(k.VerificationKey())
	if err != nil {
		return fileRecord{}, err
	}
	rec.KEKID, rec.WrappedDEK, rec.PrivateCT, rec.PublicJWK = s.kek.ID(), wrapped, ct, pubJWK
	return rec, nil
}

func (s *FileStore) decode(ctx context.Context, rec fileRecord, version, gen int) (Key, error) {
	if rec.KEKID != s.kek.ID() {
		return Key{}, fmt.Errorf("%w: record has %q, store has %q", ErrKEKMismatch, rec.KEKID, s.kek.ID())
	}
	recAAD := aadV2(rec, gen)
	if version < 2 {
		recAAD = aad(rec.ID, jose.Algorithm(rec.Alg))
	}
	pkcs8, err := envelopeOpen(ctx, s.kek, rec.PrivateCT, rec.WrappedDEK, recAAD)
	if err != nil {
		return Key{}, err
	}
	priv, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return Key{}, fmt.Errorf("parse private key: %w", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return Key{}, fmt.Errorf("private key type %T is not a crypto.Signer", priv)
	}
	// Public key is derived from the authenticated (AEAD-protected) private key,
	// never trusted from the plaintext PublicJWK field. The kid MUST equal the
	// thumbprint of that recovered public key, or a file-write attacker could
	// publish their own key under a legitimate kid and forge tokens.
	pub := signer.Public()
	tp, err := jose.Thumbprint(pub)
	if err != nil {
		return Key{}, err
	}
	if tp != rec.ID {
		return Key{}, fmt.Errorf("keystore: kid %q does not match thumbprint of private key (%q)", rec.ID, tp)
	}
	return Key{
		ID: rec.ID, Alg: jose.Algorithm(rec.Alg), State: State(rec.State),
		CreatedAt: rec.CreatedAt, PromotedAt: rec.PromotedAt,
		RetiringAt: rec.RetiringAt, RetiredAt: rec.RetiredAt,
		Private: signer, Public: pub,
	}, nil
}

// persist writes the whole store atomically. Caller must hold s.mu.
func (s *FileStore) persist(ctx context.Context) error {
	next := s.gen + 1
	doc := fileDoc{Version: fileVersion, Generation: next}
	for _, id := range s.order {
		rec, err := s.encode(ctx, s.keys[id], next)
		if err != nil {
			return err
		}
		doc.Keys = append(doc.Keys, rec)
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	tmp, err := os.CreateTemp(dir, ".keysmith-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), s.path); err != nil {
		return err
	}
	// A document carrying `next` now exists on disk, so the counter advances here
	// and not after the fsync below: if the fsync fails the caller rolls its
	// in-memory mutation back and the next write would otherwise seal a
	// *different* record set under the same generation. Two documents sharing a
	// generation is exactly the splice the generation exists to prevent — a gap
	// in the sequence is harmless, reuse is not.
	s.gen = next
	// The file's contents are fsynced above; the directory entry that points at
	// them is not, and that is the half that decides whether the rename is
	// visible after a crash. Without this, Put/Update report a key durable that
	// a power loss can still take back.
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		d.Close()
		return err
	}
	if err := d.Close(); err != nil {
		return err
	}
	// Anchor strictly after the document is durable, never before: an anchor
	// ahead of the file would make the next open refuse a legitimate store —
	// a self-inflicted brick of the platform's only signer. An anchor *behind*
	// the file is safe (the open check is doc.Generation >= anchor), so a
	// failed Set costs one generation of rollback-detection lag and a loud
	// error, nothing more.
	if s.anchor != nil {
		if err := s.anchor.Set(ctx, next); err != nil {
			return fmt.Errorf("advance generation anchor: %w", err)
		}
	}
	return nil
}

func (s *FileStore) Put(ctx context.Context, k Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[k.ID]; ok {
		return ErrDuplicate
	}
	s.keys[k.ID] = k
	s.order = append(s.order, k.ID)
	if err := s.persist(ctx); err != nil {
		delete(s.keys, k.ID)
		s.order = s.order[:len(s.order)-1]
		return err
	}
	return nil
}

func (s *FileStore) Update(ctx context.Context, k Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.keys[k.ID]
	if !ok {
		return ErrNotFound
	}
	s.keys[k.ID] = k
	if err := s.persist(ctx); err != nil {
		s.keys[k.ID] = prev
		return err
	}
	return nil
}

func (s *FileStore) Get(_ context.Context, id string) (Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[id]
	if !ok {
		return Key{}, ErrNotFound
	}
	return k, nil
}

func (s *FileStore) List(_ context.Context) ([]Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Key, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, s.keys[id])
	}
	return out, nil
}
