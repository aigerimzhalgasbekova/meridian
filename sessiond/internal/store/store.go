// Package store implements the distributed session store: many stateless
// sessiond nodes sharing session truth in Redis.
//
// Design in brief:
//
//   - Tokens are opaque 256-bit random strings. Redis stores only the
//     SHA-256 of the token, so a Redis snapshot or a read-only compromise
//     yields nothing presentable. The hash doubles as the session ID that
//     admin surfaces (list, revoke-by-id) operate on.
//   - Expiry is enforced twice: a sliding idle window implemented as the
//     Redis key TTL (renewed on touch) and an absolute lifetime stored as a
//     deadline field inside the record. The TTL is always clamped to the
//     deadline, and the touch script re-checks the deadline, so no sequence
//     of touches can extend a session past its absolute cap — even under
//     clock skew between nodes.
//   - A per-user ZSET (score = creation time) indexes sessions for
//     concurrent-session limits and revoke-all. Dead members are pruned
//     lazily on create/list, so the index needs no background reaper.
//   - Every check-and-act sequence (create with limit enforcement, touch
//     with deadline check, rotate) is a Lua script: one atomic step on the
//     single point of truth, immune to interleaving from other nodes.
//   - Each node keeps a tiny local cache of validation results so the hot
//     path (validate) does not hit Redis on every request. Revocations are
//     broadcast over Redis pub/sub and drop cache entries immediately; if a
//     broadcast is missed, entries self-expire after CacheTTL, so a revoked
//     session can outlive its revocation on a given node by at most CacheTTL
//     (default 2s). That bounded window is the consistency contract.
package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

// Errors returned by the store. Callers must not distinguish "never existed"
// from "expired" or "revoked" — that distinction is a validity oracle.
var (
	ErrNotFound     = errors.New("store: session not found")
	ErrSessionLimit = errors.New("store: concurrent session limit reached")
	ErrBadName      = errors.New("store: realm and user id must match [A-Za-z0-9._-]{1,64}")
)

// EvictPolicy decides what happens when a user is at the session cap.
type EvictPolicy string

const (
	// EvictOldest silently revokes the user's oldest session to make room.
	EvictOldest EvictPolicy = "evict-oldest"
	// Reject refuses the new session with ErrSessionLimit.
	Reject EvictPolicy = "reject"
)

// revocationChannel carries revoked session IDs to every node's local cache.
const revocationChannel = "sessiond:revoked"

// nameRE guards realm/user inputs that are spliced into Redis key names.
var nameRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Session is the metadata stored per session. ID is the hex SHA-256 of the
// opaque token; the token itself is never stored.
type Session struct {
	ID          string    `json:"id"`
	UserID      string    `json:"user_id"`
	Realm       string    `json:"realm"`
	IP          string    `json:"ip"`
	UAHash      string    `json:"ua_hash"` // truncated SHA-256 of the user agent
	CreatedAt   time.Time `json:"created_at"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	AbsDeadline time.Time `json:"absolute_deadline"`
}

// Config tunes the store. Zero values get production-shaped defaults.
type Config struct {
	// IdleTTL is the sliding window: a session untouched this long dies.
	IdleTTL time.Duration // default 30m
	// AbsoluteTTL caps total session lifetime; never extended by touches.
	AbsoluteTTL time.Duration // default 12h
	// MaxPerUser is the concurrent-session cap per (realm, user).
	MaxPerUser int         // default 5
	Policy     EvictPolicy // default EvictOldest
	// CacheTTL bounds how long a node may serve a stale validation result
	// after a missed revocation broadcast. Keep it small (seconds).
	CacheTTL time.Duration // default 2s
	// Now supplies the clock; defaults to time.Now. Injectable for tests.
	Now    func() time.Time
	Logger *slog.Logger
}

// Store is one node's handle on the shared session state.
type Store struct {
	rdb   redis.UniversalClient
	cfg   Config
	cache *cache
}

// New builds a Store around an existing Redis client.
func New(rdb redis.UniversalClient, cfg Config) *Store {
	if cfg.IdleTTL <= 0 {
		cfg.IdleTTL = 30 * time.Minute
	}
	if cfg.AbsoluteTTL <= 0 {
		cfg.AbsoluteTTL = 12 * time.Hour
	}
	if cfg.MaxPerUser <= 0 {
		cfg.MaxPerUser = 5
	}
	if cfg.Policy == "" {
		cfg.Policy = EvictOldest
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 2 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Store{rdb: rdb, cfg: cfg, cache: newCache(cfg.CacheTTL, cfg.Now)}
}

func sessKey(id string) string { return "sess:" + id }

func userKey(realm, uid string) string { return "usersess:" + realm + ":" + uid + ":sessions" }

// hashToken derives the session ID from a presented token.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// uaFingerprint stores a short hash of the user agent, not the raw string:
// enough to spot a change, no PII-ish payload in Redis.
func uaFingerprint(ua string) string {
	h := sha256.Sum256([]byte(ua))
	return hex.EncodeToString(h[:8])
}

// newToken returns a 256-bit random opaque token.
func newToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func checkNames(realm, uid string) error {
	if !nameRE.MatchString(realm) || !nameRE.MatchString(uid) {
		return ErrBadName
	}
	return nil
}

// Create mints a new session for (realm, userID), enforcing the per-user cap
// atomically. It returns the opaque token (shown once, never stored) and the
// session metadata.
func (s *Store) Create(ctx context.Context, realm, userID, ip, userAgent string) (string, Session, error) {
	if err := checkNames(realm, userID); err != nil {
		return "", Session{}, err
	}
	token, err := newToken()
	if err != nil {
		return "", Session{}, err
	}
	id := hashToken(token)
	now := s.cfg.Now()
	deadline := now.Add(s.cfg.AbsoluteTTL)

	res, err := createScript.Run(ctx, s.rdb,
		[]string{userKey(realm, userID)},
		now.UnixMilli(),
		s.cfg.IdleTTL.Milliseconds(),
		deadline.UnixMilli(),
		s.cfg.MaxPerUser,
		string(s.cfg.Policy),
		id, userID, realm, ip, uaFingerprint(userAgent),
	).Result()
	if err != nil {
		return "", Session{}, fmt.Errorf("store: create: %w", err)
	}
	switch v := res.(type) {
	case string:
		if v == "LIMIT" {
			return "", Session{}, ErrSessionLimit
		}
		return "", Session{}, fmt.Errorf("store: create: unexpected reply %q", v)
	case []any:
		// Evicted session IDs: broadcast so every node's cache drops them.
		for _, e := range v {
			if evicted, ok := e.(string); ok {
				s.broadcastRevocation(ctx, evicted)
			}
		}
	}
	sess := Session{
		ID: id, UserID: userID, Realm: realm, IP: ip, UAHash: uaFingerprint(userAgent),
		CreatedAt: now, LastSeenAt: now, AbsDeadline: deadline,
	}
	return token, sess, nil
}

// Validate checks a presented token and, on success, renews the sliding idle
// window (capped by the absolute deadline). Results are served from the local
// cache for up to CacheTTL, which also bounds how stale the LastSeenAt renewal
// can be.
func (s *Store) Validate(ctx context.Context, token string) (Session, error) {
	id := hashToken(token)
	if sess, negative, ok := s.cache.get(id); ok {
		if negative {
			return Session{}, ErrNotFound
		}
		return sess, nil
	}
	// readAt is when Redis answered, not when the entry is filled: the cache
	// entry describes truth as of readAt, so its lifetime must be measured
	// from there. Otherwise a slow round trip widens the staleness bound to
	// CacheTTL + RTT, and the documented "at most CacheTTL" stops being true.
	readAt := s.cfg.Now().UnixMilli()
	res, err := touchScript.Run(ctx, s.rdb, []string{sessKey(id)},
		readAt, s.cfg.IdleTTL.Milliseconds(), id).Result()
	if err != nil {
		return Session{}, fmt.Errorf("store: validate: %w", err)
	}
	fields, ok := res.([]any)
	if !ok || len(fields) == 0 {
		s.cache.putNegative(id, readAt)
		return Session{}, ErrNotFound
	}
	sess, err := parseSession(id, fields)
	if err != nil {
		return Session{}, err
	}
	s.cache.put(id, sess, readAt)
	return sess, nil
}

// Rotate atomically replaces the session behind oldToken with a fresh session
// ID (fixation defense on login / privilege elevation). Creation time and the
// absolute deadline carry over — rotation must never extend a lifetime. The
// old ID is invalidated in the same script and its revocation broadcast.
func (s *Store) Rotate(ctx context.Context, oldToken, ip, userAgent string) (string, Session, error) {
	oldID := hashToken(oldToken)
	newTok, err := newToken()
	if err != nil {
		return "", Session{}, err
	}
	newID := hashToken(newTok)
	now := s.cfg.Now()

	res, err := rotateScript.Run(ctx, s.rdb,
		[]string{sessKey(oldID), sessKey(newID)},
		now.UnixMilli(), s.cfg.IdleTTL.Milliseconds(),
		oldID, newID, ip, uaFingerprint(userAgent),
	).Result()
	if err != nil {
		return "", Session{}, fmt.Errorf("store: rotate: %w", err)
	}
	fields, ok := res.([]any)
	if !ok || len(fields) == 0 {
		return "", Session{}, ErrNotFound
	}
	s.broadcastRevocation(ctx, oldID)
	sess, err := parseSession(newID, fields)
	if err != nil {
		return "", Session{}, err
	}
	sess.IP, sess.UAHash = ip, uaFingerprint(userAgent)
	s.cache.put(newID, sess, now.UnixMilli())
	return newTok, sess, nil
}

// RevokeToken revokes the session behind a presented token (logout).
func (s *Store) RevokeToken(ctx context.Context, token string) error {
	return s.RevokeID(ctx, hashToken(token))
}

// RevokeID revokes a session by its server-side ID (admin surface).
// Revocation is idempotent: revoking a dead session returns nil.
func (s *Store) RevokeID(ctx context.Context, id string) error {
	n, err := revokeScript.Run(ctx, s.rdb, []string{sessKey(id)}, id).Int64()
	if err != nil {
		return fmt.Errorf("store: revoke: %w", err)
	}
	// The API stays non-oracular (always 204), but the operator running an
	// emergency kill needs to know whether it hit anything — a mistyped or
	// wrong-cased ID is otherwise indistinguishable from a successful revoke.
	s.cfg.Logger.Info("session revoked", "session_id", id, "matched", n == 1)
	s.broadcastRevocation(ctx, id)
	return nil
}

// RevokeUser revokes every session of (realm, userID) — global logout. It
// returns the number of sessions revoked.
func (s *Store) RevokeUser(ctx context.Context, realm, userID string) (int, error) {
	if err := checkNames(realm, userID); err != nil {
		return 0, err
	}
	res, err := revokeUserScript.Run(ctx, s.rdb, []string{userKey(realm, userID)}).Result()
	if err != nil {
		return 0, fmt.Errorf("store: revoke user: %w", err)
	}
	ids, _ := res.([]any)
	for _, v := range ids {
		if id, ok := v.(string); ok {
			s.broadcastRevocation(ctx, id)
		}
	}
	return len(ids), nil
}

// List returns the live sessions of (realm, userID), oldest first, pruning
// index entries whose session keys have expired.
func (s *Store) List(ctx context.Context, realm, userID string) ([]Session, error) {
	if err := checkNames(realm, userID); err != nil {
		return nil, err
	}
	uk := userKey(realm, userID)
	members, err := s.rdb.ZRange(ctx, uk, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("store: list: %w", err)
	}
	// One clock reading governs the whole listing, matching how the scripts
	// pin one clock per call.
	now := s.cfg.Now()
	sessions := make([]Session, 0, len(members))
	for _, id := range members {
		m, err := s.rdb.HGetAll(ctx, sessKey(id)).Result()
		if err != nil {
			return nil, fmt.Errorf("store: list: %w", err)
		}
		if len(m) == 0 {
			// Expired but still indexed: prune lazily.
			_ = s.rdb.ZRem(ctx, uk, id).Err()
			continue
		}
		sess, err := parseSessionMap(id, m)
		if err != nil {
			return nil, err
		}
		if !sess.AbsDeadline.After(now) {
			// Past its absolute cap despite a live TTL (clock skew, restored
			// snapshot). touchScript refuses this session, so List — the
			// surface an operator reads before deciding what to revoke — must
			// not report it as live either.
			_ = s.rdb.ZRem(ctx, uk, id).Err()
			_ = s.rdb.Del(ctx, sessKey(id)).Err()
			continue
		}
		sessions = append(sessions, sess)
	}
	return sessions, nil
}

// Run subscribes to the revocation channel and keeps the local cache honest.
// It blocks until ctx is done or the subscription is lost. If the
// subscription is lost the cache is flushed before returning: a node that is
// not listening must not serve cached results built while it was.
// Even a node that never runs this loop stays within the CacheTTL staleness
// bound — the subscription only makes invalidation immediate.
func (s *Store) Run(ctx context.Context) error {
	sub := s.rdb.Subscribe(ctx, revocationChannel)
	defer sub.Close()
	if _, err := sub.Receive(ctx); err != nil {
		return fmt.Errorf("store: subscribe: %w", err)
	}
	ch := sub.Channel()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-ch:
			if !ok {
				s.cache.flush()
				return errors.New("store: revocation subscription lost")
			}
			s.cache.remove(msg.Payload)
		}
	}
}

// broadcastRevocation drops the entry locally and tells every other node to.
// The local drop is unconditional so the revoking node never trusts pub/sub
// for its own correctness.
func (s *Store) broadcastRevocation(ctx context.Context, id string) {
	s.cache.remove(id)
	if err := s.rdb.Publish(ctx, revocationChannel, id).Err(); err != nil {
		// Non-fatal by design: Redis truth is already updated, and remote
		// caches self-expire within CacheTTL.
		s.cfg.Logger.Warn("revocation broadcast failed", "session_id", id, "err", err)
	}
}

// parseSession decodes the flat field/value array HGETALL returns from Lua.
func parseSession(id string, flat []any) (Session, error) {
	m := make(map[string]string, len(flat)/2)
	for i := 0; i+1 < len(flat); i += 2 {
		k, _ := flat[i].(string)
		v, _ := flat[i+1].(string)
		m[k] = v
	}
	return parseSessionMap(id, m)
}

func parseSessionMap(id string, m map[string]string) (Session, error) {
	ms := func(field string) (time.Time, error) {
		n, err := strconv.ParseInt(m[field], 10, 64)
		if err != nil {
			return time.Time{}, fmt.Errorf("store: corrupt session %s field %s: %w", id, field, err)
		}
		return time.UnixMilli(n), nil
	}
	created, err := ms("created_ms")
	if err != nil {
		return Session{}, err
	}
	seen, err := ms("seen_ms")
	if err != nil {
		return Session{}, err
	}
	deadline, err := ms("deadline_ms")
	if err != nil {
		return Session{}, err
	}
	return Session{
		ID: id, UserID: m["uid"], Realm: m["realm"], IP: m["ip"], UAHash: m["ua"],
		CreatedAt: created, LastSeenAt: seen, AbsDeadline: deadline,
	}, nil
}
