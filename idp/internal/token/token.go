// Package token issues the three token kinds: JWT access tokens and ID tokens
// (signed remotely by keysmith), and opaque rotating refresh tokens.
package token

import (
	"context"
	"time"

	"github.com/aikazzh/portfolio/idp/internal/oauth"
	"github.com/aikazzh/portfolio/idp/internal/secrets"
	"github.com/aikazzh/portfolio/idp/internal/storage"
	"github.com/aikazzh/portfolio/keysmith/jose"
)

// Signer abstracts keysmith's signing API (the keysmith client implements it;
// tests may substitute a local signer).
type Signer interface {
	Sign(ctx context.Context, claims jose.Claims, ttl time.Duration) (string, error)
}

// Issuer mints tokens for a deployment (one issuer base URL, many realms).
type Issuer struct {
	// BaseURL is the externally visible idp origin, e.g. https://idp.example.
	BaseURL string
	Signer  Signer
	Now     func() time.Time
}

// IssuerURL returns the per-realm issuer identifier.
func (i *Issuer) IssuerURL(realm string) string {
	return i.BaseURL + "/realms/" + realm
}

func (i *Issuer) now() time.Time {
	if i.Now != nil {
		return i.Now()
	}
	return time.Now()
}

// AccessTokenInput carries everything an access token asserts.
type AccessTokenInput struct {
	Realm    storage.Realm
	ClientID string
	// UserID is empty for client_credentials tokens.
	UserID   string
	Scopes   oauth.Scopes
	AuthTime time.Time
}

// AccessToken mints a JWT access token.
//
// Shape notes:
//   - aud is the realm's issuer URL. It must carry the tenant: all realms are
//     signed by one keysmith key set, so a realm-agnostic audience would let a
//     resource server that checks the conventional signature + aud + scope
//     accept another tenant's token, with only iss telling them apart. Using
//     the issuer URL collapses the two checks into one value.
//   - azp (authorized party) carries the client_id per OIDC Core §2 usage.
//   - sub is the user (or the client_id for service tokens, prefixed so a
//     service identity can never collide with a user ID).
func (i *Issuer) AccessToken(ctx context.Context, in AccessTokenInput) (string, error) {
	sub := in.UserID
	if sub == "" {
		sub = "service:" + in.ClientID
	}
	claims := jose.Claims{
		Issuer:   i.IssuerURL(in.Realm.Name),
		Subject:  sub,
		Audience: []string{i.IssuerURL(in.Realm.Name)},
		ID:       secrets.New("jti_"),
		Extra: map[string]any{
			"azp":   in.ClientID,
			"scope": in.Scopes.String(),
		},
	}
	if !in.AuthTime.IsZero() {
		claims.Extra["auth_time"] = in.AuthTime.Unix()
	}
	return i.Signer.Sign(ctx, claims, in.Realm.AccessTokenTTL)
}

// IDTokenInput carries the OIDC ID token inputs.
type IDTokenInput struct {
	Realm    storage.Realm
	ClientID string
	User     storage.User
	Nonce    string
	AuthTime time.Time
	Scopes   oauth.Scopes
}

// IDToken mints an OIDC Core ID token. Claim release follows the requested
// scopes (profile, email); the ID token lifetime is tied to the access token
// TTL (it is an authentication statement, not an API credential).
func (i *Issuer) IDToken(ctx context.Context, in IDTokenInput) (string, error) {
	extra := map[string]any{
		"azp":       in.ClientID,
		"auth_time": in.AuthTime.Unix(),
	}
	if in.Nonce != "" {
		extra["nonce"] = in.Nonce
	}
	for k, v := range ProfileClaims(in.User, in.Scopes) {
		extra[k] = v
	}
	claims := jose.Claims{
		Issuer:   i.IssuerURL(in.Realm.Name),
		Subject:  in.User.ID,
		Audience: []string{in.ClientID},
		Extra:    extra,
	}
	return i.Signer.Sign(ctx, claims, in.Realm.AccessTokenTTL)
}

// ProfileClaims maps scopes to released user claims (OIDC Core §5.4).
// Shared by the ID token and the userinfo endpoint so the two can never
// drift apart.
func ProfileClaims(u storage.User, scopes oauth.Scopes) map[string]any {
	out := map[string]any{}
	if scopes.Has(oauth.ScopeProfile) {
		if u.Name != "" {
			out["name"] = u.Name
		}
		if u.GivenName != "" {
			out["given_name"] = u.GivenName
		}
		if u.FamilyName != "" {
			out["family_name"] = u.FamilyName
		}
		out["preferred_username"] = u.Username
	}
	if scopes.Has(oauth.ScopeEmail) && u.Email != "" {
		out["email"] = u.Email
		out["email_verified"] = u.EmailVerified
	}
	return out
}

// NewRefreshToken creates the first generation of a refresh-token family.
// Returns the plaintext (for the client) and the storage record.
func NewRefreshToken(realm storage.Realm, clientID, userID string, scopes oauth.Scopes, authTime time.Time, nonce string, now time.Time) (string, storage.RefreshToken) {
	plaintext := secrets.New("rt_")
	return plaintext, storage.RefreshToken{
		TokenHash: secrets.Hash(plaintext),
		RealmName: realm.Name,
		FamilyID:  secrets.New("rtf_"),
		ClientID:  clientID,
		UserID:    userID,
		Scopes:    scopes,
		AuthTime:  authTime,
		Nonce:     nonce,
		ExpiresAt: now.Add(realm.RefreshTokenTTL),
		CreatedAt: now,
	}
}

// RotateRefreshToken derives the successor generation: same family, same
// absolute expiry, fresh token value.
func RotateRefreshToken(prev storage.RefreshToken, now time.Time) (string, storage.RefreshToken) {
	plaintext := secrets.New("rt_")
	return plaintext, storage.RefreshToken{
		TokenHash: secrets.Hash(plaintext),
		RealmName: prev.RealmName,
		FamilyID:  prev.FamilyID,
		ClientID:  prev.ClientID,
		UserID:    prev.UserID,
		Scopes:    prev.Scopes,
		AuthTime:  prev.AuthTime,
		Nonce:     prev.Nonce,
		ExpiresAt: prev.ExpiresAt, // absolute lifetime is inherited, never extended
		CreatedAt: now,
	}
}
