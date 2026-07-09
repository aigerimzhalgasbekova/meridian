package server

import (
	"context"
	"sync"
	"time"
)

// LocalGuard is the default LoginGuard: a fixed-window failure counter per
// (realm, username) and per (realm, IP), in process memory. It provides
// baseline brute-force protection when sentinel isn't deployed; the sentinel
// client replaces it in the full platform.
type LocalGuard struct {
	now func() time.Time

	mu       sync.Mutex
	failures map[string]*window
}

type window struct {
	start time.Time
	count int
}

const (
	guardWindow      = 15 * time.Minute
	guardMaxUser     = 10 // failures per username per window
	guardMaxIP       = 50 // failures per IP per window (many users behind NAT)
	guardMaxTracked  = 100_000
)

// NewLocalGuard builds a LocalGuard with an injectable clock.
func NewLocalGuard(now func() time.Time) *LocalGuard {
	return &LocalGuard{now: now, failures: make(map[string]*window)}
}

func (g *LocalGuard) count(key string) int {
	w, ok := g.failures[key]
	if !ok || g.now().Sub(w.start) > guardWindow {
		return 0
	}
	return w.count
}

func (g *LocalGuard) incr(key string) {
	w, ok := g.failures[key]
	if !ok || g.now().Sub(w.start) > guardWindow {
		if len(g.failures) >= guardMaxTracked {
			// Degrade by forgetting rather than growing without bound.
			g.failures = make(map[string]*window)
		}
		g.failures[key] = &window{start: g.now(), count: 1}
		return
	}
	w.count++
}

func (g *LocalGuard) Allow(_ context.Context, realm, username, ip string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.count(realm+"\x00u\x00"+username) < guardMaxUser &&
		g.count(realm+"\x00i\x00"+ip) < guardMaxIP
}

func (g *LocalGuard) RecordFailure(_ context.Context, realm, username, ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.incr(realm + "\x00u\x00" + username)
	g.incr(realm + "\x00i\x00" + ip)
}

func (g *LocalGuard) RecordSuccess(_ context.Context, realm, username, ip string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.failures, realm+"\x00u\x00"+username)
	// The IP window is left intact: success from an IP doesn't absolve
	// its failures against other accounts (credential-stuffing pattern).
}
