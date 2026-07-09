// Package storage defines the idp's persistence model and store interfaces.
//
// Secrets never touch storage in plaintext: authorization codes, refresh
// tokens, device codes, and login session IDs are stored as SHA-256 hashes of
// high-entropy random values; client secrets and user passwords are stored as
// hashes appropriate to their entropy class (SHA-256 for generated 256-bit
// secrets, Argon2id for human passwords).
package storage

import (
	"errors"
	"time"

	"github.com/aikazzh/portfolio/idp/internal/oauth"
)

// Common store errors.
var (
	ErrNotFound  = errors.New("storage: not found")
	ErrDuplicate = errors.New("storage: already exists")
	// ErrConsumed signals an atomic single-use item was already used.
	ErrConsumed = errors.New("storage: already consumed")
)

// Realm is an isolated tenant: its own users, clients, consents and issuer.
type Realm struct {
	// Name is the URL-safe unique identifier ("acme"); it appears in the
	// issuer URL: https://idp.example/realms/acme
	Name        string
	DisplayName string

	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration // absolute family lifetime
	SessionTTL      time.Duration

	CreatedAt time.Time
}

// Client is a registered OAuth 2.0 client.
type Client struct {
	RealmName string
	ClientID  string
	// SecretHash is SHA-256 of the client secret; empty for public clients.
	SecretHash []byte
	Name       string
	// RedirectURIs are matched exactly (RFC 9700 §2.1) — no wildcards, no
	// prefix matching, no ports normalization.
	RedirectURIs []string
	GrantTypes   []string
	// Public clients (native/SPA) authenticate with PKCE, not a secret.
	Public bool
	// FirstParty clients skip the consent screen.
	FirstParty bool
	// Scopes this client may request.
	Scopes    oauth.Scopes
	CreatedAt time.Time
}

// AllowsGrant reports whether the client may use the given grant type.
func (c Client) AllowsGrant(gt string) bool {
	for _, g := range c.GrantTypes {
		if g == gt {
			return true
		}
	}
	return false
}

// AllowsRedirect reports whether uri exactly matches a registered URI.
func (c Client) AllowsRedirect(uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// User is an end user within a realm.
type User struct {
	ID        string
	RealmName string
	Username  string
	Email     string
	// EmailVerified gates the email claim's verified flag and is a
	// precondition for federation account-linking.
	EmailVerified bool
	// PasswordHash is an Argon2id encoded hash (see internal/password).
	PasswordHash string
	Name         string
	GivenName    string
	FamilyName   string
	Disabled     bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// AuthCode is a single-use authorization code (stored hashed).
type AuthCode struct {
	CodeHash  string // SHA-256, base64url
	RealmName string
	ClientID  string
	UserID    string
	// RedirectURI the code was issued for; must match at redemption
	// (RFC 6749 §4.1.3).
	RedirectURI string
	Scopes      oauth.Scopes
	// Nonce from the authorization request, echoed into the ID token.
	Nonce string
	// CodeChallenge is the S256 PKCE challenge; empty only for
	// confidential clients that omitted PKCE.
	CodeChallenge string
	// AuthTime is when the user last actively authenticated.
	AuthTime  time.Time
	SessionID string
	ExpiresAt time.Time
	CreatedAt time.Time
	// Used marks a consumed code. Consumed codes are retained until expiry
	// so replays can be detected and answered by revoking what the code
	// issued (RFC 9700 §4.5.3).
	Used bool
	// IssuedFamilyID links the code to the refresh-token family it minted,
	// enabling revocation on replay.
	IssuedFamilyID string
}

// RefreshToken is one generation of a rotating refresh-token family.
type RefreshToken struct {
	TokenHash string // SHA-256, base64url
	RealmName string
	// FamilyID groups all generations descended from one authorization.
	// Reuse of a rotated generation revokes the whole family.
	FamilyID  string
	ClientID  string
	UserID    string
	Scopes    oauth.Scopes
	AuthTime  time.Time
	Nonce     string
	ExpiresAt time.Time // absolute: inherited from family start
	CreatedAt time.Time
	// RotatedAt is set when a successor was issued; presenting a rotated
	// token is the theft signal.
	RotatedAt time.Time
	Revoked   bool
}

// Consent records scopes a user has granted to a client.
type Consent struct {
	RealmName string
	UserID    string
	ClientID  string
	Scopes    oauth.Scopes
	GrantedAt time.Time
	UpdatedAt time.Time
}

// DeviceCodeStatus is the state of a device authorization (RFC 8628).
type DeviceCodeStatus string

const (
	DeviceStatusPending  DeviceCodeStatus = "pending"
	DeviceStatusApproved DeviceCodeStatus = "approved"
	DeviceStatusDenied   DeviceCodeStatus = "denied"
)

// DeviceCode is a device-flow authorization in progress.
type DeviceCode struct {
	DeviceCodeHash string // SHA-256 of the device_code
	// UserCode is the short human code (stored normalized, uppercase,
	// no separators). Low entropy by design; rate-limited at verification.
	UserCode  string
	RealmName string
	ClientID  string
	Scopes    oauth.Scopes
	Status    DeviceCodeStatus
	// UserID is set on approval.
	UserID string
	// Interval is the minimum polling interval in seconds.
	Interval     int
	ExpiresAt    time.Time
	LastPolledAt time.Time
	CreatedAt    time.Time
}

// Session is an idp login session (stored hashed).
type Session struct {
	IDHash          string
	RealmName       string
	UserID          string
	CreatedAt       time.Time
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
}
