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

func TestSweepDeletesExpired(t *testing.T) {
	s := testStore(t)
	seedRealm(t, s)
	ctx := context.Background()
	now := time.Now().UTC()

	// One expired auth code and one still-valid one.
	mustCreate := func(hash string, exp time.Time) {
		if err := s.AuthCodes().Create(ctx, storage.AuthCode{
			CodeHash: hash, RealmName: "test", ClientID: "c", UserID: "u",
			RedirectURI: "https://x/cb", Scopes: oauth.Scopes{"openid"},
			ExpiresAt: exp, CreatedAt: now.Add(-time.Hour),
		}); err != nil {
			t.Fatal(err)
		}
	}
	mustCreate("expired", now.Add(-time.Minute))
	mustCreate("valid", now.Add(time.Hour))
	// Expired refresh token and session.
	if err := s.RefreshTokens().Create(ctx, storage.RefreshToken{
		TokenHash: "rt", RealmName: "test", FamilyID: "f", ClientID: "c", UserID: "u",
		ExpiresAt: now.Add(-time.Minute), CreatedAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Sessions().Create(ctx, storage.Session{
		IDHash: "sess", RealmName: "test", UserID: "u",
		CreatedAt: now.Add(-time.Hour), AuthenticatedAt: now.Add(-time.Hour),
		ExpiresAt: now.Add(-time.Minute),
	}); err != nil {
		t.Fatal(err)
	}

	n, err := s.Sweep(ctx, now)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 { // expired auth code + refresh token + session
		t.Fatalf("swept %d rows, want 3", n)
	}
	// The valid code survives.
	if _, err := s.AuthCodes().Consume(ctx, "valid", now); err != nil {
		t.Fatalf("valid code was swept: %v", err)
	}
	// A second sweep with nothing expired is a no-op.
	if n, err := s.Sweep(ctx, now); err != nil || n != 0 {
		t.Fatalf("second sweep: n=%d err=%v, want 0,nil", n, err)
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

// TestTouchPollConcurrent guards the device-flow slow_down pacing: the
// previous poll time each caller gets back must reflect a genuine per-caller
// serialization on the row, not a shared pre-update snapshot. The old
// RETURNING-subquery SQL let every concurrent poller read the same stale
// (zero) previous timestamp, so all of them would appear to be the first
// poll and the interval check could be bypassed. Under the fix exactly one
// caller sees the initial (zero) value.
//
// A coordinator transaction holds the row lock while the pollers queue up, so
// they genuinely contend — fired bare, they finish microseconds apart, never
// overlap, and the old buggy SQL passes by timing luck (verified: it survived
// 10 unforced runs, and fails this version deterministically).
func TestTouchPollConcurrent(t *testing.T) {
	s := testStore(t)
	seedRealm(t, s)
	ctx := context.Background()
	now := time.Now().UTC()
	if err := s.DeviceCodes().Create(ctx, storage.DeviceCode{
		DeviceCodeHash: "dev0", UserCode: "AAAA-BBBB", RealmName: "test", ClientID: "c",
		Scopes: oauth.Scopes{"openid"}, Status: storage.DeviceStatusPending,
		Interval: 5, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}); err != nil {
		t.Fatal(err)
	}
	lock, err := s.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lock.Exec(ctx,
		`SELECT 1 FROM device_codes WHERE realm_name='test' AND device_code_hash='dev0' FOR UPDATE`); err != nil {
		t.Fatal(err)
	}
	const n = 16
	var wg sync.WaitGroup
	sawZero := make([]bool, n)
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			prev, err := s.DeviceCodes().TouchPoll(ctx, "test", "dev0", now.Add(time.Duration(i)*time.Second))
			if err != nil {
				t.Errorf("TouchPoll: %v", err)
				return
			}
			sawZero[i] = prev.IsZero()
		}(i)
	}
	// Let the pollers pile up on the row lock (each takes its statement
	// snapshot while blocked), then release them all at once.
	time.Sleep(300 * time.Millisecond)
	if err := lock.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	zeros := 0
	for _, z := range sawZero {
		if z {
			zeros++
		}
	}
	if zeros != 1 {
		t.Fatalf("%d pollers saw the initial (zero) previous timestamp, want exactly 1", zeros)
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
