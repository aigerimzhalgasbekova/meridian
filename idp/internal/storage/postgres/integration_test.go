//go:build integration

// Integration tests for the Postgres store. Run with:
//
//	TEST_DATABASE_URL=postgres://user:pass@localhost/idp_test go test -tags integration ./internal/storage/postgres/
//
// These exercise the atomic single-use operations against a real database,
// where the concurrency guarantees actually live.
package postgres

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/aikazzh/portfolio/idp/internal/oauth"
	"github.com/aikazzh/portfolio/idp/internal/storage"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	s, err := Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	// Clean slate.
	for _, tbl := range []string{"sessions", "device_codes", "consents", "refresh_tokens", "auth_codes", "users", "clients", "realms"} {
		if _, err := s.pool.Exec(ctx, "TRUNCATE "+tbl+" CASCADE"); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(s.Close)
	return s
}

func seedRealm(t *testing.T, s *Store) storage.Realm {
	t.Helper()
	r := storage.Realm{
		Name: "test", DisplayName: "Test",
		AccessTokenTTL: 10 * time.Minute, RefreshTokenTTL: 720 * time.Hour,
		SessionTTL: 8 * time.Hour, CreatedAt: time.Now().UTC(),
	}
	if err := s.Realms().Create(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestAuthCodeConsumeIsSingleUse(t *testing.T) {
	s := testStore(t)
	seedRealm(t, s)
	ctx := context.Background()
	now := time.Now().UTC()
	code := storage.AuthCode{
		CodeHash: "hash1", RealmName: "test", ClientID: "c", UserID: "u",
		RedirectURI: "https://x/cb", Scopes: oauth.Scopes{"openid"},
		ExpiresAt: now.Add(time.Minute), CreatedAt: now,
	}
	if err := s.AuthCodes().Create(ctx, code); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthCodes().Consume(ctx, "hash1", now); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	_, err := s.AuthCodes().Consume(ctx, "hash1", now)
	if err != storage.ErrConsumed {
		t.Fatalf("second consume: %v, want ErrConsumed", err)
	}
}

func TestAuthCodeConsumeConcurrent(t *testing.T) {
	s := testStore(t)
	seedRealm(t, s)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := s.AuthCodes().Create(ctx, storage.AuthCode{
		CodeHash: "race", RealmName: "test", ClientID: "c", UserID: "u",
		RedirectURI: "https://x/cb", ExpiresAt: now.Add(time.Minute), CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	const n = 16
	var wg sync.WaitGroup
	successes := make([]bool, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := s.AuthCodes().Consume(ctx, "race", now)
			successes[i] = err == nil
		}(i)
	}
	wg.Wait()
	count := 0
	for _, ok := range successes {
		if ok {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("%d concurrent consumers succeeded, want exactly 1", count)
	}
}

func TestRefreshRotateConcurrent(t *testing.T) {
	s := testStore(t)
	seedRealm(t, s)
	ctx := context.Background()
	now := time.Now().UTC()
	orig := storage.RefreshToken{
		TokenHash: "rt0", RealmName: "test", FamilyID: "fam", ClientID: "c", UserID: "u",
		Scopes: oauth.Scopes{"openid"}, ExpiresAt: now.Add(720 * time.Hour), CreatedAt: now,
	}
	if err := s.RefreshTokens().Create(ctx, orig); err != nil {
		t.Fatal(err)
	}
	const n = 16
	var wg sync.WaitGroup
	successes := make([]bool, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			succ := storage.RefreshToken{
				TokenHash: "rt-succ", RealmName: "test", FamilyID: "fam", ClientID: "c", UserID: "u",
				Scopes: oauth.Scopes{"openid"}, ExpiresAt: orig.ExpiresAt, CreatedAt: now,
			}
			err := s.RefreshTokens().Rotate(ctx, "test", "rt0", succ, now)
			successes[i] = err == nil
		}(i)
	}
	wg.Wait()
	count := 0
	for _, ok := range successes {
		if ok {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("%d concurrent rotations succeeded, want exactly 1", count)
	}
}
