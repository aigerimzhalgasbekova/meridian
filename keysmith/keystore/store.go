package keystore

import (
	"context"
	"sync"
)

// Store persists managed keys. Implementations must be safe for concurrent
// use. Private key material crosses this interface; implementations that
// write to durable media must encrypt it (see FileStore).
type Store interface {
	// Put stores a new key; ErrDuplicate if the ID exists.
	Put(ctx context.Context, k Key) error
	// Update replaces an existing key's record; ErrNotFound if absent.
	Update(ctx context.Context, k Key) error
	// Get returns the key with the given ID.
	Get(ctx context.Context, id string) (Key, error)
	// List returns all keys in creation order.
	List(ctx context.Context) ([]Key, error)
}

// MemoryStore is an in-memory Store for tests and ephemeral dev instances.
type MemoryStore struct {
	mu    sync.RWMutex
	keys  map[string]Key
	order []string
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{keys: make(map[string]Key)}
}

func (s *MemoryStore) Put(_ context.Context, k Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[k.ID]; ok {
		return ErrDuplicate
	}
	s.keys[k.ID] = k
	s.order = append(s.order, k.ID)
	return nil
}

func (s *MemoryStore) Update(_ context.Context, k Key) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.keys[k.ID]; !ok {
		return ErrNotFound
	}
	s.keys[k.ID] = k
	return nil
}

func (s *MemoryStore) Get(_ context.Context, id string) (Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.keys[id]
	if !ok {
		return Key{}, ErrNotFound
	}
	return k, nil
}

func (s *MemoryStore) List(_ context.Context) ([]Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Key, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, s.keys[id])
	}
	return out, nil
}
