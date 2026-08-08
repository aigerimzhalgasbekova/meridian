// Package storagetest is the shared conformance suite for storage.Store
// implementations. Both backends must satisfy it identically: memory runs it
// Docker-free on every `go test`, postgres runs it under `-tags integration`
// against a real database.
//
// It exists because the server tests all run against memory, so postgres could
// (and did) diverge silently — a schema the database rejected outright, nil
// slices binding as SQL NULL against NOT NULL columns. Anything the server
// relies on belongs here, asserted once, verified twice.
//
// Where the backends legitimately differ the suite stays deliberately loose:
//
//   - List order. postgres sorts by created_at; memory ranges a map. Compared
//     as sets.
//   - Consent scope order. postgres merges with array_agg(DISTINCT), which
//     sorts; memory appends. Compared as sets.
//   - nil vs empty slices. postgres reads back []string{} where memory kept
//     nil. Only emptiness is asserted.
//   - Timestamp precision. TIMESTAMPTZ is microsecond-resolution and comes
//     back in the connection's zone, so times are compared with Equal, never
//     ==, and seeds are truncated to microseconds.
//
// Consume's 24h post-expiry garbage collection is memory-only (postgres relies
// on Sweep), so the suite only asserts the shared window before it.
package storagetest

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/aikazzh/portfolio/idp/internal/oauth"
	"github.com/aikazzh/portfolio/idp/internal/storage"
)

// NewStore builds an empty Store. It is called once per subtest, so each gets
// a clean backend.
type NewStore func(t *testing.T) storage.Store

// RunStoreContract asserts the behaviour every storage.Store must share.
// Subtests are not parallel: the postgres factory truncates shared tables.
func RunStoreContract(t *testing.T, newStore NewStore) {
	t.Helper()
	for _, tc := range []struct {
		name string
		run  func(*testing.T, storage.Store, time.Time)
	}{
		{"Realms", realmContract},
		{"Clients", clientContract},
		{"Users", userContract},
		{"AuthCodes", authCodeContract},
		{"RefreshTokens", refreshContract},
		{"Consents", consentContract},
		{"DeviceCodes", deviceContract},
		{"Sessions", sessionContract},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStore(t)
			// Microsecond truncation: TIMESTAMPTZ cannot hold Go's nanoseconds,
			// so an untruncated seed never round-trips equal.
			now := time.Now().UTC().Truncate(time.Microsecond)
			seedRealm(t, s, now)
			tc.run(t, s, now)
		})
	}
}

const realm = "test"

func seedRealm(t *testing.T, s storage.Store, now time.Time) {
	t.Helper()
	err := s.Realms().Create(context.Background(), storage.Realm{
		Name: realm, DisplayName: "Test",
		AccessTokenTTL: 10 * time.Minute, RefreshTokenTTL: 720 * time.Hour,
		SessionTTL: 8 * time.Hour, CreatedAt: now,
	})
	if err != nil {
		t.Fatalf("seed realm: %v", err)
	}
}

// --- realms ---

func realmContract(t *testing.T, s storage.Store, now time.Time) {
	ctx := context.Background()
	rs := s.Realms()

	got, err := rs.Get(ctx, realm)
	mustNoErr(t, "Get", err)
	if got.Name != realm || got.DisplayName != "Test" {
		t.Errorf("Get: got %q/%q", got.Name, got.DisplayName)
	}
	// TTLs survive the BIGINT round trip.
	if got.AccessTokenTTL != 10*time.Minute || got.RefreshTokenTTL != 720*time.Hour || got.SessionTTL != 8*time.Hour {
		t.Errorf("Get: TTLs %v/%v/%v", got.AccessTokenTTL, got.RefreshTokenTTL, got.SessionTTL)
	}
	sameTime(t, "Get CreatedAt", got.CreatedAt, now)

	mustErr(t, "Create duplicate", rs.Create(ctx, storage.Realm{Name: realm, CreatedAt: now}), storage.ErrDuplicate)

	_, err = rs.Get(ctx, "nope")
	mustErr(t, "Get missing", err, storage.ErrNotFound)

	mustNoErr(t, "Create second", rs.Create(ctx, storage.Realm{
		Name: "other", DisplayName: "Other", CreatedAt: now.Add(time.Second),
	}))
	list, err := rs.List(ctx)
	mustNoErr(t, "List", err)
	sameSet(t, "List", names(list, func(r storage.Realm) string { return r.Name }), []string{realm, "other"})
}

// --- clients ---

func clientContract(t *testing.T, s storage.Store, now time.Time) {
	ctx := context.Background()
	cs := s.Clients()

	full := storage.Client{
		RealmName: realm, ClientID: "web", SecretHash: []byte{1, 2, 3}, Name: "Web",
		RedirectURIs: []string{"https://x/cb"}, GrantTypes: []string{"authorization_code"},
		Public: false, FirstParty: true, Scopes: oauth.Scopes{"openid", "profile"}, CreatedAt: now,
	}
	mustNoErr(t, "Create", cs.Create(ctx, full))

	got, err := cs.Get(ctx, realm, "web")
	mustNoErr(t, "Get", err)
	if got.Name != "Web" || got.Public || !got.FirstParty {
		t.Errorf("Get: %+v", got)
	}
	if !slices.Equal(got.SecretHash, []byte{1, 2, 3}) {
		t.Errorf("Get SecretHash: %v", got.SecretHash)
	}
	sameSet(t, "Get RedirectURIs", got.RedirectURIs, []string{"https://x/cb"})
	sameSet(t, "Get GrantTypes", got.GrantTypes, []string{"authorization_code"})
	sameSet(t, "Get Scopes", got.Scopes, []string{"openid", "profile"})
	sameTime(t, "Get CreatedAt", got.CreatedAt, now)

	// A public client leaves every slice and the secret nil: they must persist
	// as empty, not as SQL NULL against NOT NULL columns.
	mustNoErr(t, "Create public", cs.Create(ctx, storage.Client{
		RealmName: realm, ClientID: "cli", Name: "CLI", Public: true, CreatedAt: now,
	}))
	pub, err := cs.Get(ctx, realm, "cli")
	mustNoErr(t, "Get public", err)
	if len(pub.SecretHash) != 0 || len(pub.RedirectURIs) != 0 || len(pub.GrantTypes) != 0 || len(pub.Scopes) != 0 {
		t.Errorf("Get public: want all empty, got %+v", pub)
	}
	if !pub.Public {
		t.Error("Get public: Public flag lost")
	}

	mustErr(t, "Create duplicate", cs.Create(ctx, full), storage.ErrDuplicate)

	_, err = cs.Get(ctx, realm, "nope")
	mustErr(t, "Get missing", err, storage.ErrNotFound)
	_, err = cs.Get(ctx, "other", "web")
	mustErr(t, "Get cross-realm", err, storage.ErrNotFound)

	list, err := cs.List(ctx, realm)
	mustNoErr(t, "List", err)
	sameSet(t, "List", names(list, func(c storage.Client) string { return c.ClientID }), []string{"web", "cli"})

	mustNoErr(t, "Delete", cs.Delete(ctx, realm, "cli"))
	mustErr(t, "Delete missing", cs.Delete(ctx, realm, "cli"), storage.ErrNotFound)
}

// --- users ---

func userContract(t *testing.T, s storage.Store, now time.Time) {
	ctx := context.Background()
	us := s.Users()

	alice := storage.User{
		ID: "u1", RealmName: realm, Username: "Alice", Email: "a@x.test", EmailVerified: true,
		PasswordHash: "argon2id$...", Name: "Alice A", GivenName: "Alice", FamilyName: "A",
		CreatedAt: now, UpdatedAt: now,
	}
	mustNoErr(t, "Create", us.Create(ctx, alice))

	got, err := us.Get(ctx, realm, "u1")
	mustNoErr(t, "Get", err)
	if got.Username != "Alice" || got.Email != "a@x.test" || !got.EmailVerified || got.Disabled {
		t.Errorf("Get: %+v", got)
	}
	sameTime(t, "Get CreatedAt", got.CreatedAt, now)

	// Usernames are matched case-insensitively on lookup and on uniqueness.
	for _, name := range []string{"Alice", "alice", "ALICE"} {
		byName, err := us.GetByUsername(ctx, realm, name)
		mustNoErr(t, "GetByUsername "+name, err)
		if byName.ID != "u1" {
			t.Errorf("GetByUsername %q: got id %q", name, byName.ID)
		}
	}
	_, err = us.GetByUsername(ctx, realm, "nope")
	mustErr(t, "GetByUsername missing", err, storage.ErrNotFound)

	mustErr(t, "Create duplicate id", us.Create(ctx, alice), storage.ErrDuplicate)
	mustErr(t, "Create duplicate username (case-insensitive)", us.Create(ctx, storage.User{
		ID: "u2", RealmName: realm, Username: "ALICE", CreatedAt: now, UpdatedAt: now,
	}), storage.ErrDuplicate)

	// Update: mutate, rename, then collide.
	alice.Disabled = true
	alice.Username = "alice2"
	alice.UpdatedAt = now.Add(time.Minute)
	mustNoErr(t, "Update", us.Update(ctx, alice))
	got, err = us.Get(ctx, realm, "u1")
	mustNoErr(t, "Get after Update", err)
	if !got.Disabled || got.Username != "alice2" {
		t.Errorf("Update: %+v", got)
	}
	sameTime(t, "Update UpdatedAt", got.UpdatedAt, now.Add(time.Minute))
	// The old username is free again.
	_, err = us.GetByUsername(ctx, realm, "Alice")
	mustErr(t, "GetByUsername after rename", err, storage.ErrNotFound)

	mustNoErr(t, "Create bob", us.Create(ctx, storage.User{
		ID: "u2", RealmName: realm, Username: "bob", CreatedAt: now, UpdatedAt: now,
	}))
	bob, err := us.Get(ctx, realm, "u2")
	mustNoErr(t, "Get bob", err)
	bob.Username = "ALICE2" // taken by u1, differing only in case
	mustErr(t, "Update to taken username", us.Update(ctx, bob), storage.ErrDuplicate)

	mustErr(t, "Update missing", us.Update(ctx, storage.User{
		ID: "ghost", RealmName: realm, Username: "ghost", CreatedAt: now, UpdatedAt: now,
	}), storage.ErrNotFound)

	_, err = us.Get(ctx, realm, "nope")
	mustErr(t, "Get missing", err, storage.ErrNotFound)

	list, err := us.List(ctx, realm)
	mustNoErr(t, "List", err)
	sameSet(t, "List", names(list, func(u storage.User) string { return u.ID }), []string{"u1", "u2"})
}

// --- auth codes ---

func authCodeContract(t *testing.T, s storage.Store, now time.Time) {
	ctx := context.Background()
	acs := s.AuthCodes()

	code := storage.AuthCode{
		CodeHash: "c1", RealmName: realm, ClientID: "web", UserID: "u1",
		RedirectURI: "https://x/cb", Scopes: oauth.Scopes{"openid"},
		Nonce: "n", CodeChallenge: "cc", AuthTime: now, SessionID: "sess",
		ExpiresAt: now.Add(time.Minute), CreatedAt: now,
	}
	mustNoErr(t, "Create", acs.Create(ctx, code))
	mustErr(t, "Create duplicate", acs.Create(ctx, code), storage.ErrDuplicate)

	// Get reads without consuming, so the caller can validate and sign first.
	peek, err := acs.Get(ctx, realm, "c1")
	mustNoErr(t, "Get", err)
	if peek.Used || peek.ClientID != "web" {
		t.Errorf("Get: %+v", peek)
	}
	_, err = acs.Get(ctx, realm, "nope")
	mustErr(t, "Get missing", err, storage.ErrNotFound)

	// Auth codes are realm-scoped like every other table: another realm can
	// neither read nor burn this code.
	_, err = acs.Get(ctx, "other", "c1")
	mustErr(t, "Get cross-realm", err, storage.ErrNotFound)
	_, err = acs.Consume(ctx, "other", "c1", now)
	mustErr(t, "Consume cross-realm", err, storage.ErrNotFound)
	mustErr(t, "MarkFamily cross-realm", acs.MarkFamily(ctx, "other", "c1", "fam"), storage.ErrNotFound)
	stillThere, err := acs.Get(ctx, realm, "c1")
	mustNoErr(t, "Get after cross-realm Consume", err)
	if stillThere.Used {
		t.Error("Consume from another realm burned the code")
	}

	got, err := acs.Consume(ctx, realm, "c1", now)
	mustNoErr(t, "Consume", err)
	if got.ClientID != "web" || got.UserID != "u1" || got.RedirectURI != "https://x/cb" ||
		got.Nonce != "n" || got.CodeChallenge != "cc" || got.SessionID != "sess" {
		t.Errorf("Consume: %+v", got)
	}
	sameSet(t, "Consume Scopes", got.Scopes, []string{"openid"})
	sameTime(t, "Consume AuthTime", got.AuthTime, now)

	// Replay returns the consumed record so the caller can revoke what it minted.
	replay, err := acs.Consume(ctx, realm, "c1", now)
	mustErr(t, "Consume replay", err, storage.ErrConsumed)
	if !replay.Used || replay.CodeHash != "c1" {
		t.Errorf("Consume replay: want the used record, got %+v", replay)
	}

	// Replay is still detectable after expiry (before any sweep).
	replay, err = acs.Consume(ctx, realm, "c1", now.Add(time.Hour))
	mustErr(t, "Consume replay after expiry", err, storage.ErrConsumed)
	if !replay.Used {
		t.Error("Consume replay after expiry: want the used record")
	}

	mustNoErr(t, "MarkFamily", acs.MarkFamily(ctx, realm, "c1", "fam1"))
	replay, err = acs.Consume(ctx, realm, "c1", now)
	mustErr(t, "Consume after MarkFamily", err, storage.ErrConsumed)
	if replay.IssuedFamilyID != "fam1" {
		t.Errorf("MarkFamily: got %q, want fam1", replay.IssuedFamilyID)
	}
	mustErr(t, "MarkFamily missing", acs.MarkFamily(ctx, realm, "nope", "f"), storage.ErrNotFound)

	// An unused code past expiry is gone, not consumed.
	mustNoErr(t, "Create expiring", acs.Create(ctx, storage.AuthCode{
		CodeHash: "c2", RealmName: realm, ClientID: "web", UserID: "u1",
		RedirectURI: "https://x/cb", AuthTime: now, ExpiresAt: now.Add(time.Minute), CreatedAt: now,
	}))
	_, err = acs.Consume(ctx, realm, "c2", now.Add(time.Hour))
	mustErr(t, "Consume expired", err, storage.ErrNotFound)

	_, err = acs.Consume(ctx, realm, "nope", now)
	mustErr(t, "Consume unknown", err, storage.ErrNotFound)
}

// --- refresh tokens ---

func refreshContract(t *testing.T, s storage.Store, now time.Time) {
	ctx := context.Background()
	rts := s.RefreshTokens()

	mk := func(hash, fam string) storage.RefreshToken {
		return storage.RefreshToken{
			TokenHash: hash, RealmName: realm, FamilyID: fam, ClientID: "web", UserID: "u1",
			Scopes: oauth.Scopes{"openid", "offline_access"}, AuthTime: now, Nonce: "n",
			ExpiresAt: now.Add(720 * time.Hour), CreatedAt: now,
		}
	}
	mustNoErr(t, "Create", rts.Create(ctx, mk("rt0", "fam")))
	mustErr(t, "Create duplicate", rts.Create(ctx, mk("rt0", "fam")), storage.ErrDuplicate)

	got, err := rts.Get(ctx, realm, "rt0")
	mustNoErr(t, "Get", err)
	if got.FamilyID != "fam" || got.ClientID != "web" || got.Nonce != "n" || got.Revoked {
		t.Errorf("Get: %+v", got)
	}
	if !got.RotatedAt.IsZero() {
		t.Errorf("Get: fresh token has RotatedAt %v", got.RotatedAt)
	}
	sameSet(t, "Get Scopes", got.Scopes, []string{"openid", "offline_access"})
	sameTime(t, "Get ExpiresAt", got.ExpiresAt, now.Add(720*time.Hour))

	fam, err := rts.FamilyOf(ctx, realm, "rt0")
	mustNoErr(t, "FamilyOf", err)
	if fam != "fam" {
		t.Errorf("FamilyOf: got %q", fam)
	}
	_, err = rts.FamilyOf(ctx, realm, "nope")
	mustErr(t, "FamilyOf missing", err, storage.ErrNotFound)

	mustErr(t, "Rotate missing", rts.Rotate(ctx, realm, "nope", mk("x", "fam"), now), storage.ErrNotFound)

	mustNoErr(t, "Rotate", rts.Rotate(ctx, realm, "rt0", mk("rt1", "fam"), now))
	old, err := rts.Get(ctx, realm, "rt0")
	mustNoErr(t, "Get rotated", err)
	if old.RotatedAt.IsZero() {
		t.Error("Rotate: predecessor RotatedAt not set")
	}
	sameTime(t, "Rotate RotatedAt", old.RotatedAt, now)
	if _, err := rts.Get(ctx, realm, "rt1"); err != nil {
		t.Errorf("Rotate: successor missing: %v", err)
	}

	// Presenting a rotated generation is the theft signal, and must not mint again.
	mustErr(t, "Rotate replay", rts.Rotate(ctx, realm, "rt0", mk("rt2", "fam"), now), storage.ErrConsumed)
	_, err = rts.Get(ctx, realm, "rt2")
	mustErr(t, "Rotate replay minted a successor", err, storage.ErrNotFound)

	mustNoErr(t, "RevokeFamily", rts.RevokeFamily(ctx, realm, "fam"))
	for _, h := range []string{"rt0", "rt1"} {
		got, err := rts.Get(ctx, realm, h)
		mustNoErr(t, "Get after RevokeFamily", err)
		if !got.Revoked {
			t.Errorf("RevokeFamily: %s not revoked", h)
		}
	}
	// A revoked (but never rotated) token cannot rotate.
	mustErr(t, "Rotate revoked", rts.Rotate(ctx, realm, "rt1", mk("rt3", "fam"), now), storage.ErrConsumed)

	// Revoking an unknown family is a no-op, not an error.
	mustNoErr(t, "RevokeFamily missing", rts.RevokeFamily(ctx, realm, "ghost"))
}

// --- consents ---

func consentContract(t *testing.T, s storage.Store, now time.Time) {
	ctx := context.Background()
	cs := s.Consents()

	_, err := cs.Get(ctx, realm, "u1", "web")
	mustErr(t, "Get missing", err, storage.ErrNotFound)

	mustNoErr(t, "Upsert insert", cs.Upsert(ctx, storage.Consent{
		RealmName: realm, UserID: "u1", ClientID: "web",
		Scopes: oauth.Scopes{"openid"}, GrantedAt: now, UpdatedAt: now,
	}))
	got, err := cs.Get(ctx, realm, "u1", "web")
	mustNoErr(t, "Get", err)
	sameSet(t, "Get Scopes", got.Scopes, []string{"openid"})
	sameTime(t, "Get GrantedAt", got.GrantedAt, now)

	// Upsert unions scopes rather than replacing them, and dedupes.
	later := now.Add(time.Minute)
	mustNoErr(t, "Upsert merge", cs.Upsert(ctx, storage.Consent{
		RealmName: realm, UserID: "u1", ClientID: "web",
		Scopes: oauth.Scopes{"openid", "profile"}, GrantedAt: later, UpdatedAt: later,
	}))
	got, err = cs.Get(ctx, realm, "u1", "web")
	mustNoErr(t, "Get after merge", err)
	sameSet(t, "merged Scopes", got.Scopes, []string{"openid", "profile"})
	sameTime(t, "merged UpdatedAt", got.UpdatedAt, later)

	mustNoErr(t, "Delete", cs.Delete(ctx, realm, "u1", "web"))
	mustErr(t, "Delete missing", cs.Delete(ctx, realm, "u1", "web"), storage.ErrNotFound)
}

// --- device codes ---

func deviceContract(t *testing.T, s storage.Store, now time.Time) {
	ctx := context.Background()
	ds := s.DeviceCodes()

	dc := storage.DeviceCode{
		DeviceCodeHash: "d1", UserCode: "AAAA-BBBB", RealmName: realm, ClientID: "web",
		Scopes: oauth.Scopes{"openid"}, Status: storage.DeviceStatusPending,
		Interval: 5, ExpiresAt: now.Add(time.Hour), CreatedAt: now,
	}
	mustNoErr(t, "Create", ds.Create(ctx, dc))
	mustErr(t, "Create duplicate hash", ds.Create(ctx, dc), storage.ErrDuplicate)
	dup := dc
	dup.DeviceCodeHash = "d2"
	mustErr(t, "Create duplicate user_code", ds.Create(ctx, dup), storage.ErrDuplicate)

	got, err := ds.GetByDeviceCode(ctx, realm, "d1")
	mustNoErr(t, "GetByDeviceCode", err)
	if got.Status != storage.DeviceStatusPending || got.Interval != 5 || got.UserID != "" {
		t.Errorf("GetByDeviceCode: %+v", got)
	}
	if !got.LastPolledAt.IsZero() {
		t.Errorf("GetByDeviceCode: fresh code has LastPolledAt %v", got.LastPolledAt)
	}
	sameSet(t, "Scopes", got.Scopes, []string{"openid"})
	sameTime(t, "ExpiresAt", got.ExpiresAt, now.Add(time.Hour))

	byUC, err := ds.GetByUserCode(ctx, realm, "AAAA-BBBB")
	mustNoErr(t, "GetByUserCode", err)
	if byUC.DeviceCodeHash != "d1" {
		t.Errorf("GetByUserCode: got %q", byUC.DeviceCodeHash)
	}
	_, err = ds.GetByUserCode(ctx, realm, "ZZZZ-ZZZZ")
	mustErr(t, "GetByUserCode missing", err, storage.ErrNotFound)
	_, err = ds.GetByDeviceCode(ctx, realm, "nope")
	mustErr(t, "GetByDeviceCode missing", err, storage.ErrNotFound)

	// TouchPoll hands back the previous poll time so the caller can pace polling.
	prev, err := ds.TouchPoll(ctx, realm, "d1", now)
	mustNoErr(t, "TouchPoll first", err)
	if !prev.IsZero() {
		t.Errorf("TouchPoll first: got %v, want zero", prev)
	}
	prev, err = ds.TouchPoll(ctx, realm, "d1", now.Add(3*time.Second))
	mustNoErr(t, "TouchPoll second", err)
	sameTime(t, "TouchPoll second previous", prev, now)
	_, err = ds.TouchPoll(ctx, realm, "nope", now)
	mustErr(t, "TouchPoll missing", err, storage.ErrNotFound)

	mustErr(t, "SetStatus missing", ds.SetStatus(ctx, realm, "nope", storage.DeviceStatusApproved, "u1", now), storage.ErrNotFound)
	mustNoErr(t, "SetStatus approve", ds.SetStatus(ctx, realm, "d1", storage.DeviceStatusApproved, "u1", now))
	got, err = ds.GetByDeviceCode(ctx, realm, "d1")
	mustNoErr(t, "Get after SetStatus", err)
	if got.Status != storage.DeviceStatusApproved || got.UserID != "u1" {
		t.Errorf("SetStatus: %+v", got)
	}
	// The approving session's authentication time rides along to redemption.
	sameTime(t, "SetStatus AuthTime", got.AuthTime, now)
	// Only pending → approved/denied is allowed; the transition is single-use.
	mustErr(t, "SetStatus twice", ds.SetStatus(ctx, realm, "d1", storage.DeviceStatusDenied, "u2", now), storage.ErrConsumed)

	mustNoErr(t, "Delete", ds.Delete(ctx, realm, "d1"))
	mustErr(t, "Delete missing", ds.Delete(ctx, realm, "d1"), storage.ErrNotFound)
	// The user_code index is released with the row.
	_, err = ds.GetByUserCode(ctx, realm, "AAAA-BBBB")
	mustErr(t, "GetByUserCode after Delete", err, storage.ErrNotFound)
	mustNoErr(t, "Create reuses freed user_code", ds.Create(ctx, dup))
}

// --- sessions ---

func sessionContract(t *testing.T, s storage.Store, now time.Time) {
	ctx := context.Background()
	ss := s.Sessions()

	mk := func(hash, user string) storage.Session {
		return storage.Session{
			IDHash: hash, RealmName: realm, UserID: user,
			CreatedAt: now, AuthenticatedAt: now, ExpiresAt: now.Add(8 * time.Hour),
		}
	}
	mustNoErr(t, "Create", ss.Create(ctx, mk("s1", "u1")))
	mustErr(t, "Create duplicate", ss.Create(ctx, mk("s1", "u1")), storage.ErrDuplicate)

	got, err := ss.Get(ctx, realm, "s1")
	mustNoErr(t, "Get", err)
	if got.UserID != "u1" {
		t.Errorf("Get: %+v", got)
	}
	sameTime(t, "Get AuthenticatedAt", got.AuthenticatedAt, now)
	sameTime(t, "Get ExpiresAt", got.ExpiresAt, now.Add(8*time.Hour))

	_, err = ss.Get(ctx, realm, "nope")
	mustErr(t, "Get missing", err, storage.ErrNotFound)

	mustNoErr(t, "Delete", ss.Delete(ctx, realm, "s1"))
	_, err = ss.Get(ctx, realm, "s1")
	mustErr(t, "Get after Delete", err, storage.ErrNotFound)
	mustErr(t, "Delete missing", ss.Delete(ctx, realm, "s1"), storage.ErrNotFound)

	// DeleteByUser is scoped to the user and is a no-op when nothing matches.
	mustNoErr(t, "Create s2", ss.Create(ctx, mk("s2", "u1")))
	mustNoErr(t, "Create s3", ss.Create(ctx, mk("s3", "u1")))
	mustNoErr(t, "Create s4", ss.Create(ctx, mk("s4", "u2")))
	mustNoErr(t, "DeleteByUser", ss.DeleteByUser(ctx, realm, "u1"))
	for _, h := range []string{"s2", "s3"} {
		_, err := ss.Get(ctx, realm, h)
		mustErr(t, "Get after DeleteByUser", err, storage.ErrNotFound)
	}
	if _, err := ss.Get(ctx, realm, "s4"); err != nil {
		t.Errorf("DeleteByUser removed another user's session: %v", err)
	}
	mustNoErr(t, "DeleteByUser no match", ss.DeleteByUser(ctx, realm, "ghost"))
}

// --- assertions ---

func mustNoErr(t *testing.T, what string, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", what, err)
	}
}

func mustErr(t *testing.T, what string, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("%s: got %v, want %v", what, got, want)
	}
}

// sameTime compares instants, not representations: postgres returns TIMESTAMPTZ
// in the connection's zone, so == would fail on an equal instant.
func sameTime(t *testing.T, what string, got, want time.Time) {
	t.Helper()
	if !got.Equal(want) {
		t.Errorf("%s: got %v, want %v", what, got, want)
	}
}

// sameSet compares contents, ignoring order (backends disagree) and treating
// nil and empty as equal (postgres reads arrays back as non-nil empty slices).
func sameSet[S ~[]string](t *testing.T, what string, got, want S) {
	t.Helper()
	g, w := slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want))
	if !slices.Equal(g, w) {
		t.Errorf("%s: got %v, want %v (order-insensitive)", what, g, w)
	}
}

func names[T any](xs []T, f func(T) string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = f(x)
	}
	return out
}
