package store

import (
	"sync"
	"time"
)

// cache is the per-node validation cache. It exists so the hot path
// (validate) does not pay a Redis round trip per request, and it is the
// reason revocation needs pub/sub at all.
//
// Correctness argument: an entry lives at most ttl (CacheTTL). Revocations
// arriving over pub/sub delete entries immediately; a *missed* broadcast
// therefore extends a revoked session on this node by at most ttl. The cache
// never writes back to Redis, so it can only ever serve a stale read — it
// cannot resurrect or extend a session in the shared truth.
type cache struct {
	mu      sync.RWMutex
	ttl     int64 // milliseconds
	now     func() int64
	entries map[string]cacheEntry
}

type cacheEntry struct {
	sess     Session
	negative bool // cached miss: session known-dead as of expiry window
	expires  int64
}

// maxEntries bounds memory; past it, new entries are simply not cached.
// ponytail: no LRU — entries self-expire in seconds, so pressure is transient.
const maxEntries = 100_000

func newCache(ttl time.Duration, now func() time.Time) *cache {
	return &cache{
		ttl:     ttl.Milliseconds(),
		now:     func() int64 { return now().UnixMilli() },
		entries: make(map[string]cacheEntry),
	}
}

func (c *cache) get(id string) (sess Session, negative, ok bool) {
	c.mu.RLock()
	e, ok := c.entries[id]
	c.mu.RUnlock()
	if !ok || c.now() >= e.expires {
		return Session{}, false, false
	}
	return e.sess, e.negative, true
}

func (c *cache) put(id string, sess Session) {
	c.set(id, cacheEntry{sess: sess, expires: c.now() + c.ttl})
}

func (c *cache) putNegative(id string) {
	c.set(id, cacheEntry{negative: true, expires: c.now() + c.ttl})
}

func (c *cache) set(id string, e cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= maxEntries {
		if _, exists := c.entries[id]; !exists {
			// Drop expired entries; if still full, skip caching this one.
			now := c.now()
			for k, v := range c.entries {
				if now >= v.expires {
					delete(c.entries, k)
				}
			}
			if len(c.entries) >= maxEntries {
				return
			}
		}
	}
	c.entries[id] = e
}

func (c *cache) remove(id string) {
	c.mu.Lock()
	delete(c.entries, id)
	c.mu.Unlock()
}

func (c *cache) flush() {
	c.mu.Lock()
	c.entries = make(map[string]cacheEntry)
	c.mu.Unlock()
}
