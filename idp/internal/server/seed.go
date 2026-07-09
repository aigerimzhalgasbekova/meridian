package server

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/aikazzh/portfolio/idp/internal/oauth"
	"github.com/aikazzh/portfolio/idp/internal/password"
	"github.com/aikazzh/portfolio/idp/internal/storage"
)

// SeedDev populates a store with a demo realm for local development:
//
//	realm:  demo
//	user:   alice / password123 (verified email)
//	client: web-app     (confidential, secret "web-app-secret", first-party)
//	client: spa         (public, PKCE-only)
//	client: cli         (device flow)
//	client: service     (client_credentials)
func SeedDev(ctx context.Context, store storage.Store) error {
	now := time.Now().UTC()
	realm := storage.Realm{
		Name:            "demo",
		DisplayName:     "Demo Realm",
		AccessTokenTTL:  10 * time.Minute,
		RefreshTokenTTL: 30 * 24 * time.Hour,
		SessionTTL:      8 * time.Hour,
		CreatedAt:       now,
	}
	if err := store.Realms().Create(ctx, realm); err != nil {
		return err
	}
	hash, err := password.Hash("password123", password.Default)
	if err != nil {
		return err
	}
	if err := store.Users().Create(ctx, storage.User{
		ID: "usr_alice", RealmName: "demo",
		Username: "alice", Email: "alice@example.com", EmailVerified: true,
		PasswordHash: hash, Name: "Alice Liddell", GivenName: "Alice", FamilyName: "Liddell",
		CreatedAt: now, UpdatedAt: now,
	}); err != nil {
		return err
	}
	secretHash := sha256.Sum256([]byte("web-app-secret"))
	clients := []storage.Client{
		{
			RealmName: "demo", ClientID: "web-app", SecretHash: secretHash[:],
			Name: "Demo Web App", FirstParty: true,
			RedirectURIs: []string{"http://localhost:3000/callback"},
			GrantTypes:   []string{"authorization_code", "refresh_token"},
			Scopes:       oauth.Scopes{"openid", "profile", "email", "offline_access"},
			CreatedAt:    now,
		},
		{
			RealmName: "demo", ClientID: "spa", Public: true,
			Name:         "Demo SPA",
			RedirectURIs: []string{"http://localhost:5173/callback"},
			GrantTypes:   []string{"authorization_code", "refresh_token"},
			Scopes:       oauth.Scopes{"openid", "profile", "email", "offline_access"},
			CreatedAt:    now,
		},
		{
			RealmName: "demo", ClientID: "cli", Public: true,
			Name:       "Demo CLI",
			GrantTypes: []string{"urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
			Scopes:     oauth.Scopes{"openid", "profile", "offline_access"},
			CreatedAt:  now,
		},
		{
			RealmName: "demo", ClientID: "service", SecretHash: secretHash[:],
			Name:       "Demo Service",
			GrantTypes: []string{"client_credentials"},
			Scopes:     oauth.Scopes{"inventory:read", "inventory:write"},
			CreatedAt:  now,
		},
	}
	for _, c := range clients {
		if err := store.Clients().Create(ctx, c); err != nil {
			return err
		}
	}
	return nil
}
