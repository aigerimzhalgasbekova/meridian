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
	"sync"
	"time"

	"github.com/aikazzh/portfolio/keysmith/jose"
)

// FileStore persists keys to a single JSON file with private key material
// envelope-encrypted. Writes are atomic (temp file + rename) and fsynced.
// Suitable for single-writer deployments; multi-node deployments should back
// keysmith with a database store and run one rotation leader.
type FileStore struct {
	path string
	kek  KEK

	mu    sync.RWMutex
	keys  map[string]Key
	order []string
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
	Version int          `json:"version"`
	Keys    []fileRecord `json:"keys"`
}

// OpenFileStore loads (or initializes) the store at path.
func OpenFileStore(ctx context.Context, path string, kek KEK) (*FileStore, error) {
	s := &FileStore{path: path, kek: kek, keys: make(map[string]Key)}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, fmt.Errorf("keystore: read %s: %w", path, err)
	}
	var doc fileDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("keystore: parse %s: %w", path, err)
	}
	for _, rec := range doc.Keys {
		k, err := s.decode(ctx, rec)
		if err != nil {
			return nil, fmt.Errorf("keystore: key %q: %w", rec.ID, err)
		}
		s.keys[k.ID] = k
		s.order = append(s.order, k.ID)
	}
	return s, nil
}

func aad(id string, alg jose.Algorithm) []byte {
	return []byte("keysmith:key:" + id + ":" + string(alg))
}

func (s *FileStore) encode(ctx context.Context, k Key) (fileRecord, error) {
	pkcs8, err := x509.MarshalPKCS8PrivateKey(k.Private)
	if err != nil {
		return fileRecord{}, fmt.Errorf("marshal private key: %w", err)
	}
	ct, wrapped, err := envelopeSeal(ctx, s.kek, pkcs8, aad(k.ID, k.Alg))
	if err != nil {
		return fileRecord{}, err
	}
	pubJWK, err := jose.PublicJWK(k.VerificationKey())
	if err != nil {
		return fileRecord{}, err
	}
	return fileRecord{
		ID: k.ID, Alg: string(k.Alg), State: string(k.State),
		CreatedAt: k.CreatedAt, PromotedAt: k.PromotedAt,
		RetiringAt: k.RetiringAt, RetiredAt: k.RetiredAt,
		KEKID: s.kek.ID(), WrappedDEK: wrapped, PrivateCT: ct, PublicJWK: pubJWK,
	}, nil
}

func (s *FileStore) decode(ctx context.Context, rec fileRecord) (Key, error) {
	if rec.KEKID != s.kek.ID() {
		return Key{}, fmt.Errorf("%w: record has %q, store has %q", ErrKEKMismatch, rec.KEKID, s.kek.ID())
	}
	pkcs8, err := envelopeOpen(ctx, s.kek, rec.PrivateCT, rec.WrappedDEK, aad(rec.ID, jose.Algorithm(rec.Alg)))
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
	doc := fileDoc{Version: 1}
	for _, id := range s.order {
		rec, err := s.encode(ctx, s.keys[id])
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
	return os.Rename(tmp.Name(), s.path)
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
