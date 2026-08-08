// Package memory is an in-memory storage.Store for tests and single-node dev.
// One mutex guards everything: the atomic operations (Consume, Rotate,
// SetStatus, TouchPoll) get their atomicity from it directly.
package memory

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/aikazzh/portfolio/idp/internal/storage"
)

// Store implements storage.Store in memory.
type Store struct {
	mu sync.Mutex

	realms   map[string]storage.Realm
	clients  map[string]storage.Client       // key: realm/clientID
	users    map[string]storage.User         // key: realm/id
	byUser   map[string]string               // key: realm/username(lower) → realm/id
	codes    map[string]storage.AuthCode     // key: realm/codeHash
	refresh  map[string]storage.RefreshToken // key: realm/hash
	consents map[string]storage.Consent      // key: realm/user/client
	devices  map[string]storage.DeviceCode   // key: realm/deviceHash
	byUC     map[string]string               // key: realm/userCode → realm/deviceHash
	sessions map[string]storage.Session      // key: realm/idHash
}

// New returns an empty Store.
func New() *Store {
	return &Store{
		realms:   map[string]storage.Realm{},
		clients:  map[string]storage.Client{},
		users:    map[string]storage.User{},
		byUser:   map[string]string{},
		codes:    map[string]storage.AuthCode{},
		refresh:  map[string]storage.RefreshToken{},
		consents: map[string]storage.Consent{},
		devices:  map[string]storage.DeviceCode{},
		byUC:     map[string]string{},
		sessions: map[string]storage.Session{},
	}
}

func key(parts ...string) string { return strings.Join(parts, "\x00") }

func (s *Store) Realms() storage.RealmStore               { return (*realms)(s) }
func (s *Store) Clients() storage.ClientStore             { return (*clients)(s) }
func (s *Store) Users() storage.UserStore                 { return (*users)(s) }
func (s *Store) AuthCodes() storage.AuthCodeStore         { return (*codes)(s) }
func (s *Store) RefreshTokens() storage.RefreshTokenStore { return (*refresh)(s) }
func (s *Store) Consents() storage.ConsentStore           { return (*consents)(s) }
func (s *Store) DeviceCodes() storage.DeviceCodeStore     { return (*devices)(s) }
func (s *Store) Sessions() storage.SessionStore           { return (*sessions)(s) }

// --- realms ---

type realms Store

func (s *realms) Create(_ context.Context, r storage.Realm) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.realms[r.Name]; ok {
		return storage.ErrDuplicate
	}
	s.realms[r.Name] = r
	return nil
}

func (s *realms) Get(_ context.Context, name string) (storage.Realm, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.realms[name]
	if !ok {
		return storage.Realm{}, storage.ErrNotFound
	}
	return r, nil
}

func (s *realms) List(_ context.Context) ([]storage.Realm, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]storage.Realm, 0, len(s.realms))
	for _, r := range s.realms {
		out = append(out, r)
	}
	return out, nil
}

// --- clients ---

type clients Store

func (s *clients) Create(_ context.Context, c storage.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(c.RealmName, c.ClientID)
	if _, ok := s.clients[k]; ok {
		return storage.ErrDuplicate
	}
	s.clients[k] = c
	return nil
}

func (s *clients) Get(_ context.Context, realm, clientID string) (storage.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[key(realm, clientID)]
	if !ok {
		return storage.Client{}, storage.ErrNotFound
	}
	return c, nil
}

func (s *clients) List(_ context.Context, realm string) ([]storage.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []storage.Client
	for _, c := range s.clients {
		if c.RealmName == realm {
			out = append(out, c)
		}
	}
	return out, nil
}

func (s *clients) Delete(_ context.Context, realm, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(realm, clientID)
	if _, ok := s.clients[k]; !ok {
		return storage.ErrNotFound
	}
	delete(s.clients, k)
	return nil
}

// --- users ---

type users Store

func (s *users) Create(_ context.Context, u storage.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(u.RealmName, u.ID)
	uk := key(u.RealmName, strings.ToLower(u.Username))
	if _, ok := s.users[k]; ok {
		return storage.ErrDuplicate
	}
	if _, ok := s.byUser[uk]; ok {
		return storage.ErrDuplicate
	}
	s.users[k] = u
	s.byUser[uk] = k
	return nil
}

func (s *users) Get(_ context.Context, realm, id string) (storage.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[key(realm, id)]
	if !ok {
		return storage.User{}, storage.ErrNotFound
	}
	return u, nil
}

func (s *users) GetByUsername(_ context.Context, realm, username string) (storage.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.byUser[key(realm, strings.ToLower(username))]
	if !ok {
		return storage.User{}, storage.ErrNotFound
	}
	return s.users[k], nil
}

func (s *users) Update(_ context.Context, u storage.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(u.RealmName, u.ID)
	old, ok := s.users[k]
	if !ok {
		return storage.ErrNotFound
	}
	if !strings.EqualFold(old.Username, u.Username) {
		newUK := key(u.RealmName, strings.ToLower(u.Username))
		if _, taken := s.byUser[newUK]; taken {
			return storage.ErrDuplicate
		}
		delete(s.byUser, key(u.RealmName, strings.ToLower(old.Username)))
		s.byUser[newUK] = k
	}
	s.users[k] = u
	return nil
}

func (s *users) List(_ context.Context, realm string) ([]storage.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []storage.User
	for _, u := range s.users {
		if u.RealmName == realm {
			out = append(out, u)
		}
	}
	return out, nil
}

// --- auth codes ---

type codes Store

func (s *codes) Create(_ context.Context, c storage.AuthCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(c.RealmName, c.CodeHash)
	if _, ok := s.codes[k]; ok {
		return storage.ErrDuplicate
	}
	s.codes[k] = c
	return nil
}

func (s *codes) Get(_ context.Context, realm, codeHash string) (storage.AuthCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.codes[key(realm, codeHash)]
	if !ok {
		return storage.AuthCode{}, storage.ErrNotFound
	}
	return c, nil
}

func (s *codes) Consume(_ context.Context, realm, codeHash string, now time.Time) (storage.AuthCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(realm, codeHash)
	c, ok := s.codes[k]
	if !ok {
		return storage.AuthCode{}, storage.ErrNotFound
	}
	// Retain used codes until well past expiry for replay detection, then
	// garbage-collect opportunistically.
	if now.After(c.ExpiresAt.Add(24 * time.Hour)) {
		delete(s.codes, k)
		return storage.AuthCode{}, storage.ErrNotFound
	}
	if c.Used {
		return c, storage.ErrConsumed
	}
	if now.After(c.ExpiresAt) {
		return storage.AuthCode{}, storage.ErrNotFound
	}
	c.Used = true
	s.codes[k] = c
	return c, nil
}

func (s *codes) MarkFamily(_ context.Context, realm, codeHash, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(realm, codeHash)
	c, ok := s.codes[k]
	if !ok {
		return storage.ErrNotFound
	}
	c.IssuedFamilyID = familyID
	s.codes[k] = c
	return nil
}

// --- refresh tokens ---

type refresh Store

func (s *refresh) Create(_ context.Context, t storage.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(t.RealmName, t.TokenHash)
	if _, ok := s.refresh[k]; ok {
		return storage.ErrDuplicate
	}
	s.refresh[k] = t
	return nil
}

func (s *refresh) Get(_ context.Context, realm, tokenHash string) (storage.RefreshToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refresh[key(realm, tokenHash)]
	if !ok {
		return storage.RefreshToken{}, storage.ErrNotFound
	}
	return t, nil
}

func (s *refresh) Rotate(_ context.Context, realm, oldHash string, successor storage.RefreshToken, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(realm, oldHash)
	old, ok := s.refresh[k]
	if !ok {
		return storage.ErrNotFound
	}
	if !old.RotatedAt.IsZero() || old.Revoked {
		return storage.ErrConsumed
	}
	old.RotatedAt = now
	s.refresh[k] = old
	sk := key(successor.RealmName, successor.TokenHash)
	if _, dup := s.refresh[sk]; dup {
		return storage.ErrDuplicate
	}
	s.refresh[sk] = successor
	return nil
}

func (s *refresh) RevokeFamily(_ context.Context, realm, familyID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, t := range s.refresh {
		if t.RealmName == realm && t.FamilyID == familyID {
			t.Revoked = true
			s.refresh[k] = t
		}
	}
	return nil
}

func (s *refresh) FamilyOf(_ context.Context, realm, tokenHash string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.refresh[key(realm, tokenHash)]
	if !ok {
		return "", storage.ErrNotFound
	}
	return t.FamilyID, nil
}

// --- consents ---

type consents Store

func (s *consents) Upsert(_ context.Context, c storage.Consent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(c.RealmName, c.UserID, c.ClientID)
	if existing, ok := s.consents[k]; ok {
		merged := existing.Scopes
		for _, sc := range c.Scopes {
			if !merged.Has(sc) {
				merged = append(merged, sc)
			}
		}
		existing.Scopes = merged
		existing.UpdatedAt = c.UpdatedAt
		s.consents[k] = existing
		return nil
	}
	s.consents[k] = c
	return nil
}

func (s *consents) Get(_ context.Context, realm, userID, clientID string) (storage.Consent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.consents[key(realm, userID, clientID)]
	if !ok {
		return storage.Consent{}, storage.ErrNotFound
	}
	return c, nil
}

func (s *consents) Delete(_ context.Context, realm, userID, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(realm, userID, clientID)
	if _, ok := s.consents[k]; !ok {
		return storage.ErrNotFound
	}
	delete(s.consents, k)
	return nil
}

// --- device codes ---

type devices Store

func (s *devices) Create(_ context.Context, d storage.DeviceCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(d.RealmName, d.DeviceCodeHash)
	uk := key(d.RealmName, d.UserCode)
	if _, ok := s.devices[k]; ok {
		return storage.ErrDuplicate
	}
	if _, ok := s.byUC[uk]; ok {
		return storage.ErrDuplicate
	}
	s.devices[k] = d
	s.byUC[uk] = k
	return nil
}

func (s *devices) GetByDeviceCode(_ context.Context, realm, hash string) (storage.DeviceCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[key(realm, hash)]
	if !ok {
		return storage.DeviceCode{}, storage.ErrNotFound
	}
	return d, nil
}

func (s *devices) GetByUserCode(_ context.Context, realm, userCode string) (storage.DeviceCode, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, ok := s.byUC[key(realm, userCode)]
	if !ok {
		return storage.DeviceCode{}, storage.ErrNotFound
	}
	return s.devices[k], nil
}

func (s *devices) SetStatus(_ context.Context, realm, hash string, status storage.DeviceCodeStatus, userID string, authTime time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(realm, hash)
	d, ok := s.devices[k]
	if !ok {
		return storage.ErrNotFound
	}
	if d.Status != storage.DeviceStatusPending {
		return storage.ErrConsumed
	}
	d.Status = status
	d.UserID = userID
	d.AuthTime = authTime
	s.devices[k] = d
	return nil
}

func (s *devices) TouchPoll(_ context.Context, realm, hash string, now time.Time) (time.Time, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(realm, hash)
	d, ok := s.devices[k]
	if !ok {
		return time.Time{}, storage.ErrNotFound
	}
	prev := d.LastPolledAt
	d.LastPolledAt = now
	s.devices[k] = d
	return prev, nil
}

func (s *devices) Delete(_ context.Context, realm, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(realm, hash)
	d, ok := s.devices[k]
	if !ok {
		return storage.ErrNotFound
	}
	delete(s.devices, k)
	delete(s.byUC, key(realm, d.UserCode))
	return nil
}

// --- sessions ---

type sessions Store

func (s *sessions) Create(_ context.Context, sess storage.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(sess.RealmName, sess.IDHash)
	if _, ok := s.sessions[k]; ok {
		return storage.ErrDuplicate
	}
	s.sessions[k] = sess
	return nil
}

func (s *sessions) Get(_ context.Context, realm, idHash string) (storage.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[key(realm, idHash)]
	if !ok {
		return storage.Session{}, storage.ErrNotFound
	}
	return sess, nil
}

func (s *sessions) Delete(_ context.Context, realm, idHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := key(realm, idHash)
	if _, ok := s.sessions[k]; !ok {
		return storage.ErrNotFound
	}
	delete(s.sessions, k)
	return nil
}

func (s *sessions) DeleteByUser(_ context.Context, realm, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, sess := range s.sessions {
		if sess.RealmName == realm && sess.UserID == userID {
			delete(s.sessions, k)
		}
	}
	return nil
}
