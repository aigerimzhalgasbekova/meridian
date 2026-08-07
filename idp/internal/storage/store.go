package storage

import (
	"context"
	"time"
)

// Store aggregates the per-entity stores. Implementations: memory (tests,
// dev), postgres (production).
type Store interface {
	Realms() RealmStore
	Clients() ClientStore
	Users() UserStore
	AuthCodes() AuthCodeStore
	RefreshTokens() RefreshTokenStore
	Consents() ConsentStore
	DeviceCodes() DeviceCodeStore
	Sessions() SessionStore
}

type RealmStore interface {
	Create(ctx context.Context, r Realm) error
	Get(ctx context.Context, name string) (Realm, error)
	List(ctx context.Context) ([]Realm, error)
}

type ClientStore interface {
	Create(ctx context.Context, c Client) error
	// Get fetches a client by realm and client_id.
	Get(ctx context.Context, realm, clientID string) (Client, error)
	List(ctx context.Context, realm string) ([]Client, error)
	Delete(ctx context.Context, realm, clientID string) error
}

type UserStore interface {
	Create(ctx context.Context, u User) error
	Get(ctx context.Context, realm, id string) (User, error)
	// GetByUsername resolves the login identifier within a realm.
	GetByUsername(ctx context.Context, realm, username string) (User, error)
	Update(ctx context.Context, u User) error
	List(ctx context.Context, realm string) ([]User, error)
}

type AuthCodeStore interface {
	Create(ctx context.Context, c AuthCode) error
	// Get fetches a code without consuming it, so the caller can validate the
	// request and sign tokens before the irreversible single-use step. It
	// applies no expiry or single-use policy — Consume remains the sole
	// authority on both; Get only reports Used so a replay can be answered
	// without a wasted signing call. Unknown codes return ErrNotFound.
	Get(ctx context.Context, realm, codeHash string) (AuthCode, error)
	// Consume atomically fetches and invalidates the code. A second call
	// returns the (already used) record with ErrConsumed so the caller can
	// revoke what the first redemption issued. Expired codes return
	// ErrNotFound.
	Consume(ctx context.Context, realm, codeHash string, now time.Time) (AuthCode, error)
	// MarkFamily records the refresh-token family a consumed code issued.
	MarkFamily(ctx context.Context, realm, codeHash, familyID string) error
}

type RefreshTokenStore interface {
	Create(ctx context.Context, t RefreshToken) error
	Get(ctx context.Context, realm, tokenHash string) (RefreshToken, error)
	// Rotate atomically marks the old generation rotated and inserts the
	// successor. If the old token was already rotated it returns
	// ErrConsumed (the reuse/theft signal) without inserting.
	Rotate(ctx context.Context, realm, oldHash string, successor RefreshToken, now time.Time) error
	// RevokeFamily revokes every generation of a family.
	RevokeFamily(ctx context.Context, realm, familyID string) error
	// FamilyOf resolves a token hash to its family without consuming it.
	FamilyOf(ctx context.Context, realm, tokenHash string) (string, error)
}

type ConsentStore interface {
	// Upsert merges newly granted scopes into any existing consent.
	Upsert(ctx context.Context, c Consent) error
	Get(ctx context.Context, realm, userID, clientID string) (Consent, error)
	Delete(ctx context.Context, realm, userID, clientID string) error
}

type DeviceCodeStore interface {
	Create(ctx context.Context, d DeviceCode) error
	GetByDeviceCode(ctx context.Context, realm, deviceCodeHash string) (DeviceCode, error)
	GetByUserCode(ctx context.Context, realm, userCode string) (DeviceCode, error)
	// SetStatus transitions pending → approved/denied; any other
	// transition returns ErrConsumed. authTime is when the approving user
	// last actively authenticated, carried through to the ID token's
	// auth_time claim at redemption.
	SetStatus(ctx context.Context, realm, deviceCodeHash string, status DeviceCodeStatus, userID string, authTime time.Time) error
	// TouchPoll records a poll and returns the previous poll time so the
	// caller can enforce the interval (slow_down).
	TouchPoll(ctx context.Context, realm, deviceCodeHash string, now time.Time) (previous time.Time, err error)
	// Delete removes the device code (after successful token issuance).
	Delete(ctx context.Context, realm, deviceCodeHash string) error
}

type SessionStore interface {
	Create(ctx context.Context, s Session) error
	Get(ctx context.Context, realm, idHash string) (Session, error)
	Delete(ctx context.Context, realm, idHash string) error
	// DeleteByUser removes all of a user's sessions (admin disable path).
	DeleteByUser(ctx context.Context, realm, userID string) error
}
