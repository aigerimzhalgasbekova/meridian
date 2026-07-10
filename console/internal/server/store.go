package server

import (
	"context"
	"sort"
	"sync"
	"time"
)

// User is a managed identity. Realm places the user for scope checks: a
// realm-admin of "engineering" may only operate on engineering users.
type User struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Realm    string `json:"realm"`
	Disabled bool   `json:"disabled"`
}

// Session is an active login session, as reported by the session backend.
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
}

// UserStore is the persistence seam for users. The in-memory implementation
// backs dev and tests; a Postgres implementation is a mechanical swap
// (single table, no joins — see the idp module's storage/postgres for the
// house pattern).
type UserStore interface {
	Users(ctx context.Context) ([]User, error)
	User(ctx context.Context, id string) (User, bool, error)
	SetDisabled(ctx context.Context, id string, disabled bool) (User, bool, error)
}

// SessionProvider is the seam to sessiond. The console never owns session
// state; it lists and revokes through this interface. MemStore is the
// in-memory fake; production wires an HTTP client against sessiond's
// list/revoke API.
type SessionProvider interface {
	Sessions(ctx context.Context, userID string) ([]Session, error)
	Session(ctx context.Context, id string) (Session, bool, error)
	RevokeSession(ctx context.Context, id string) (bool, error)
}

// MemStore is the in-memory UserStore + SessionProvider used in dev and tests.
type MemStore struct {
	mu       sync.RWMutex
	users    map[string]User
	sessions map[string]Session
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{users: map[string]User{}, sessions: map[string]Session{}}
}

// AddUser inserts or replaces a user (seeding).
func (m *MemStore) AddUser(u User) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[u.ID] = u
}

// AddSession inserts a session (seeding).
func (m *MemStore) AddSession(s Session) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.ID] = s
}

func (m *MemStore) Users(context.Context) ([]User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *MemStore) User(_ context.Context, id string) (User, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[id]
	return u, ok, nil
}

func (m *MemStore) SetDisabled(_ context.Context, id string, disabled bool) (User, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	u, ok := m.users[id]
	if !ok {
		return User{}, false, nil
	}
	u.Disabled = disabled
	m.users[id] = u
	return u, true, nil
}

func (m *MemStore) Sessions(_ context.Context, userID string) ([]Session, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []Session
	for _, s := range m.sessions {
		if s.UserID == userID {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (m *MemStore) Session(_ context.Context, id string) (Session, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok, nil
}

func (m *MemStore) RevokeSession(_ context.Context, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[id]; !ok {
		return false, nil
	}
	delete(m.sessions, id)
	return true, nil
}

// AuditEvent records one mutating API call and the authorization outcome
// that gated it. Denied attempts are recorded too — an admin console that
// only logs successes hides the interesting half.
type AuditEvent struct {
	Time    time.Time `json:"time"`
	Actor   string    `json:"actor"`
	Action  string    `json:"action"`
	Target  string    `json:"target"`
	Scope   string    `json:"scope"`
	Allowed bool      `json:"allowed"`
	Detail  string    `json:"detail,omitempty"`
}

// AuditLog is an in-memory append-only trail.
// ponytail: in-memory slice; production appends to sentinel's hash-chained
// audit store via its ingest API (the platform's tamper-evidence lives there).
type AuditLog struct {
	mu     sync.RWMutex
	events []AuditEvent
}

// Append records an event.
func (l *AuditLog) Append(e AuditEvent) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

// Events returns the trail, newest first.
func (l *AuditLog) Events() []AuditEvent {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]AuditEvent, len(l.events))
	for i, e := range l.events {
		out[len(l.events)-1-i] = e
	}
	return out
}
