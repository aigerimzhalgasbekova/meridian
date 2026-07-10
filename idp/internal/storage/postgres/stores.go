package postgres

import (
	"context"
	"time"

	"github.com/aikazzh/portfolio/idp/internal/oauth"
	"github.com/aikazzh/portfolio/idp/internal/storage"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type realmStore struct{ pool *pgxpool.Pool }

func (s *realmStore) Create(ctx context.Context, r storage.Realm) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO realms (name, display_name, access_token_ttl, refresh_token_ttl, session_ttl, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		r.Name, r.DisplayName, durMillis(r.AccessTokenTTL), durMillis(r.RefreshTokenTTL),
		durMillis(r.SessionTTL), r.CreatedAt)
	return mapErr(err)
}

func scanRealm(row pgx.Row) (storage.Realm, error) {
	var r storage.Realm
	var at, rt, st int64
	err := row.Scan(&r.Name, &r.DisplayName, &at, &rt, &st, &r.CreatedAt)
	r.AccessTokenTTL, r.RefreshTokenTTL, r.SessionTTL = fromMillis(at), fromMillis(rt), fromMillis(st)
	return r, mapErr(err)
}

func (s *realmStore) Get(ctx context.Context, name string) (storage.Realm, error) {
	return scanRealm(s.pool.QueryRow(ctx,
		`SELECT name, display_name, access_token_ttl, refresh_token_ttl, session_ttl, created_at
		 FROM realms WHERE name=$1`, name))
}

func (s *realmStore) List(ctx context.Context) ([]storage.Realm, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT name, display_name, access_token_ttl, refresh_token_ttl, session_ttl, created_at
		 FROM realms ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.Realm
	for rows.Next() {
		r, err := scanRealm(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type clientStore struct{ pool *pgxpool.Pool }

func (s *clientStore) Create(ctx context.Context, c storage.Client) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO clients (realm_name, client_id, secret_hash, name, redirect_uris, grant_types, public, first_party, scopes, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		c.RealmName, c.ClientID, c.SecretHash, c.Name, c.RedirectURIs, c.GrantTypes,
		c.Public, c.FirstParty, []string(c.Scopes), c.CreatedAt)
	return mapErr(err)
}

func scanClient(row pgx.Row) (storage.Client, error) {
	var c storage.Client
	var scopes []string
	err := row.Scan(&c.RealmName, &c.ClientID, &c.SecretHash, &c.Name, &c.RedirectURIs,
		&c.GrantTypes, &c.Public, &c.FirstParty, &scopes, &c.CreatedAt)
	c.Scopes = oauth.Scopes(scopes)
	return c, mapErr(err)
}

func (s *clientStore) Get(ctx context.Context, realm, clientID string) (storage.Client, error) {
	return scanClient(s.pool.QueryRow(ctx,
		`SELECT realm_name, client_id, secret_hash, name, redirect_uris, grant_types, public, first_party, scopes, created_at
		 FROM clients WHERE realm_name=$1 AND client_id=$2`, realm, clientID))
}

func (s *clientStore) List(ctx context.Context, realm string) ([]storage.Client, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT realm_name, client_id, secret_hash, name, redirect_uris, grant_types, public, first_party, scopes, created_at
		 FROM clients WHERE realm_name=$1 ORDER BY created_at`, realm)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.Client
	for rows.Next() {
		c, err := scanClient(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *clientStore) Delete(ctx context.Context, realm, clientID string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM clients WHERE realm_name=$1 AND client_id=$2`, realm, clientID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

type userStore struct{ pool *pgxpool.Pool }

func (s *userStore) Create(ctx context.Context, u storage.User) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO users (id, realm_name, username, email, email_verified, password_hash, name, given_name, family_name, disabled, created_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		u.ID, u.RealmName, u.Username, u.Email, u.EmailVerified, u.PasswordHash,
		u.Name, u.GivenName, u.FamilyName, u.Disabled, u.CreatedAt, u.UpdatedAt)
	return mapErr(err)
}

func scanUser(row pgx.Row) (storage.User, error) {
	var u storage.User
	err := row.Scan(&u.ID, &u.RealmName, &u.Username, &u.Email, &u.EmailVerified,
		&u.PasswordHash, &u.Name, &u.GivenName, &u.FamilyName, &u.Disabled, &u.CreatedAt, &u.UpdatedAt)
	return u, mapErr(err)
}

const userCols = `id, realm_name, username, email, email_verified, password_hash, name, given_name, family_name, disabled, created_at, updated_at`

func (s *userStore) Get(ctx context.Context, realm, id string) (storage.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE realm_name=$1 AND id=$2`, realm, id))
}

func (s *userStore) GetByUsername(ctx context.Context, realm, username string) (storage.User, error) {
	return scanUser(s.pool.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE realm_name=$1 AND lower(username)=lower($2)`, realm, username))
}

func (s *userStore) Update(ctx context.Context, u storage.User) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE users SET username=$3, email=$4, email_verified=$5, password_hash=$6, name=$7,
		 given_name=$8, family_name=$9, disabled=$10, updated_at=$11 WHERE realm_name=$1 AND id=$2`,
		u.RealmName, u.ID, u.Username, u.Email, u.EmailVerified, u.PasswordHash,
		u.Name, u.GivenName, u.FamilyName, u.Disabled, u.UpdatedAt)
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func (s *userStore) List(ctx context.Context, realm string) ([]storage.User, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+userCols+` FROM users WHERE realm_name=$1 ORDER BY created_at`, realm)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []storage.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

type authCodeStore struct{ pool *pgxpool.Pool }

func (s *authCodeStore) Create(ctx context.Context, c storage.AuthCode) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO auth_codes (code_hash, realm_name, client_id, user_id, redirect_uri, scopes, nonce, code_challenge, auth_time, session_id, expires_at, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
		c.CodeHash, c.RealmName, c.ClientID, c.UserID, c.RedirectURI, []string(c.Scopes),
		c.Nonce, c.CodeChallenge, c.AuthTime, c.SessionID, c.ExpiresAt, c.CreatedAt)
	return mapErr(err)
}

// Consume flips used=false→true in one statement. The UPDATE ... WHERE used=false
// with RETURNING makes redemption atomic: the DB row lock guarantees exactly
// one caller sees used=false. A second caller updates zero rows and we then
// read back the (used) record to signal replay.
func (s *authCodeStore) Consume(ctx context.Context, codeHash string, now time.Time) (storage.AuthCode, error) {
	row := s.pool.QueryRow(ctx,
		`UPDATE auth_codes SET used=true
		 WHERE code_hash=$1 AND used=false AND expires_at > $2
		 RETURNING code_hash, realm_name, client_id, user_id, redirect_uri, scopes, nonce, code_challenge, auth_time, session_id, used, issued_family_id, expires_at, created_at`,
		codeHash, now)
	c, err := scanAuthCode(row)
	if err == nil {
		return c, nil
	}
	if err != storage.ErrNotFound {
		return storage.AuthCode{}, err
	}
	// No row updated: either unknown/expired, or already used (replay).
	c, err = scanAuthCode(s.pool.QueryRow(ctx,
		`SELECT code_hash, realm_name, client_id, user_id, redirect_uri, scopes, nonce, code_challenge, auth_time, session_id, used, issued_family_id, expires_at, created_at
		 FROM auth_codes WHERE code_hash=$1`, codeHash))
	if err != nil {
		return storage.AuthCode{}, err // ErrNotFound
	}
	if c.Used {
		return c, storage.ErrConsumed
	}
	return storage.AuthCode{}, storage.ErrNotFound // expired
}

func (s *authCodeStore) MarkFamily(ctx context.Context, codeHash, familyID string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE auth_codes SET issued_family_id=$2 WHERE code_hash=$1`, codeHash, familyID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

func scanAuthCode(row pgx.Row) (storage.AuthCode, error) {
	var c storage.AuthCode
	var scopes []string
	err := row.Scan(&c.CodeHash, &c.RealmName, &c.ClientID, &c.UserID, &c.RedirectURI, &scopes,
		&c.Nonce, &c.CodeChallenge, &c.AuthTime, &c.SessionID, &c.Used, &c.IssuedFamilyID, &c.ExpiresAt, &c.CreatedAt)
	c.Scopes = oauth.Scopes(scopes)
	return c, mapErr(err)
}

type refreshStore struct{ pool *pgxpool.Pool }

const refreshCols = `token_hash, realm_name, family_id, client_id, user_id, scopes, auth_time, nonce, expires_at, created_at, rotated_at, revoked`

func (s *refreshStore) Create(ctx context.Context, t storage.RefreshToken) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO refresh_tokens (token_hash, realm_name, family_id, client_id, user_id, scopes, auth_time, nonce, expires_at, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		t.TokenHash, t.RealmName, t.FamilyID, t.ClientID, t.UserID, []string(t.Scopes),
		t.AuthTime, t.Nonce, t.ExpiresAt, t.CreatedAt)
	return mapErr(err)
}

func scanRefresh(row pgx.Row) (storage.RefreshToken, error) {
	var t storage.RefreshToken
	var scopes []string
	var rotated *time.Time
	err := row.Scan(&t.TokenHash, &t.RealmName, &t.FamilyID, &t.ClientID, &t.UserID, &scopes,
		&t.AuthTime, &t.Nonce, &t.ExpiresAt, &t.CreatedAt, &rotated, &t.Revoked)
	t.Scopes = oauth.Scopes(scopes)
	t.RotatedAt = orZero(rotated)
	return t, mapErr(err)
}

func (s *refreshStore) Get(ctx context.Context, realm, tokenHash string) (storage.RefreshToken, error) {
	return scanRefresh(s.pool.QueryRow(ctx,
		`SELECT `+refreshCols+` FROM refresh_tokens WHERE realm_name=$1 AND token_hash=$2`, realm, tokenHash))
}

// Rotate marks the old generation rotated and inserts the successor inside one
// transaction. The UPDATE ... WHERE rotated_at IS NULL AND NOT revoked makes
// reuse detection atomic: a concurrent second redemption updates zero rows and
// is rejected with ErrConsumed, never issuing a second successor.
func (s *refreshStore) Rotate(ctx context.Context, realm, oldHash string, successor storage.RefreshToken, now time.Time) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	tag, err := tx.Exec(ctx,
		`UPDATE refresh_tokens SET rotated_at=$3
		 WHERE realm_name=$1 AND token_hash=$2 AND rotated_at IS NULL AND revoked=false`,
		realm, oldHash, now)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		// Distinguish "not there" from "already rotated/revoked".
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM refresh_tokens WHERE realm_name=$1 AND token_hash=$2)`,
			realm, oldHash).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return storage.ErrConsumed
		}
		return storage.ErrNotFound
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO refresh_tokens (token_hash, realm_name, family_id, client_id, user_id, scopes, auth_time, nonce, expires_at, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		successor.TokenHash, successor.RealmName, successor.FamilyID, successor.ClientID,
		successor.UserID, []string(successor.Scopes), successor.AuthTime, successor.Nonce,
		successor.ExpiresAt, successor.CreatedAt); err != nil {
		return mapErr(err)
	}
	return tx.Commit(ctx)
}

func (s *refreshStore) RevokeFamily(ctx context.Context, realm, familyID string) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE refresh_tokens SET revoked=true WHERE realm_name=$1 AND family_id=$2`, realm, familyID)
	return err
}

func (s *refreshStore) FamilyOf(ctx context.Context, realm, tokenHash string) (string, error) {
	var fam string
	err := s.pool.QueryRow(ctx,
		`SELECT family_id FROM refresh_tokens WHERE realm_name=$1 AND token_hash=$2`, realm, tokenHash).Scan(&fam)
	return fam, mapErr(err)
}

type consentStore struct{ pool *pgxpool.Pool }

// Upsert merges scopes at the database level with array union.
func (s *consentStore) Upsert(ctx context.Context, c storage.Consent) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO consents (realm_name, user_id, client_id, scopes, granted_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6)
		 ON CONFLICT (realm_name, user_id, client_id) DO UPDATE
		 SET scopes = (
		   SELECT array_agg(DISTINCT s) FROM unnest(consents.scopes || EXCLUDED.scopes) AS s
		 ), updated_at = EXCLUDED.updated_at`,
		c.RealmName, c.UserID, c.ClientID, []string(c.Scopes), c.GrantedAt, c.UpdatedAt)
	return mapErr(err)
}

func (s *consentStore) Get(ctx context.Context, realm, userID, clientID string) (storage.Consent, error) {
	var c storage.Consent
	var scopes []string
	err := s.pool.QueryRow(ctx,
		`SELECT realm_name, user_id, client_id, scopes, granted_at, updated_at
		 FROM consents WHERE realm_name=$1 AND user_id=$2 AND client_id=$3`,
		realm, userID, clientID).Scan(&c.RealmName, &c.UserID, &c.ClientID, &scopes, &c.GrantedAt, &c.UpdatedAt)
	c.Scopes = oauth.Scopes(scopes)
	return c, mapErr(err)
}

func (s *consentStore) Delete(ctx context.Context, realm, userID, clientID string) error {
	tag, err := s.pool.Exec(ctx,
		`DELETE FROM consents WHERE realm_name=$1 AND user_id=$2 AND client_id=$3`, realm, userID, clientID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

type deviceStore struct{ pool *pgxpool.Pool }

const deviceCols = `device_code_hash, user_code, realm_name, client_id, scopes, status, user_id, interval_secs, expires_at, last_polled_at, created_at`

func (s *deviceStore) Create(ctx context.Context, d storage.DeviceCode) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO device_codes (device_code_hash, user_code, realm_name, client_id, scopes, status, user_id, interval_secs, expires_at, created_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		d.DeviceCodeHash, d.UserCode, d.RealmName, d.ClientID, []string(d.Scopes),
		string(d.Status), d.UserID, d.Interval, d.ExpiresAt, d.CreatedAt)
	return mapErr(err)
}

func scanDevice(row pgx.Row) (storage.DeviceCode, error) {
	var d storage.DeviceCode
	var scopes []string
	var status string
	var lastPolled *time.Time
	err := row.Scan(&d.DeviceCodeHash, &d.UserCode, &d.RealmName, &d.ClientID, &scopes,
		&status, &d.UserID, &d.Interval, &d.ExpiresAt, &lastPolled, &d.CreatedAt)
	d.Scopes = oauth.Scopes(scopes)
	d.Status = storage.DeviceCodeStatus(status)
	d.LastPolledAt = orZero(lastPolled)
	return d, mapErr(err)
}

func (s *deviceStore) GetByDeviceCode(ctx context.Context, realm, hash string) (storage.DeviceCode, error) {
	return scanDevice(s.pool.QueryRow(ctx,
		`SELECT `+deviceCols+` FROM device_codes WHERE realm_name=$1 AND device_code_hash=$2`, realm, hash))
}

func (s *deviceStore) GetByUserCode(ctx context.Context, realm, userCode string) (storage.DeviceCode, error) {
	return scanDevice(s.pool.QueryRow(ctx,
		`SELECT `+deviceCols+` FROM device_codes WHERE realm_name=$1 AND user_code=$2`, realm, userCode))
}

func (s *deviceStore) SetStatus(ctx context.Context, realm, hash string, status storage.DeviceCodeStatus, userID string) error {
	tag, err := s.pool.Exec(ctx,
		`UPDATE device_codes SET status=$3, user_id=$4
		 WHERE realm_name=$1 AND device_code_hash=$2 AND status='pending'`,
		realm, hash, string(status), userID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		if err := s.pool.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM device_codes WHERE realm_name=$1 AND device_code_hash=$2)`,
			realm, hash).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return storage.ErrConsumed
		}
		return storage.ErrNotFound
	}
	return nil
}

func (s *deviceStore) TouchPoll(ctx context.Context, realm, hash string, now time.Time) (time.Time, error) {
	// The previous poll time gates slow_down (device.go), so it must be the
	// value from the row we are about to overwrite. RETURNING can't yield the
	// OLD value on PG17, and a scalar subquery in RETURNING (or a self-join)
	// reads the statement snapshot — under READ COMMITTED a second concurrent
	// poller re-locks the row via EvalPlanQual but still returns the pre-update
	// timestamp, defeating the pacing check. SELECT ... FOR UPDATE locks the row
	// and follows the update chain to the latest committed version, so the read
	// and write are serialized on the row lock.
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return time.Time{}, err
	}
	defer tx.Rollback(ctx)
	var prev *time.Time
	if err := tx.QueryRow(ctx,
		`SELECT last_polled_at FROM device_codes
		 WHERE realm_name=$1 AND device_code_hash=$2 FOR UPDATE`,
		realm, hash).Scan(&prev); err != nil {
		return time.Time{}, mapErr(err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE device_codes SET last_polled_at=$3
		 WHERE realm_name=$1 AND device_code_hash=$2`,
		realm, hash, now); err != nil {
		return time.Time{}, mapErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return time.Time{}, mapErr(err)
	}
	return orZero(prev), nil
}

func (s *deviceStore) Delete(ctx context.Context, realm, hash string) error {
	tag, err := s.pool.Exec(ctx, `DELETE FROM device_codes WHERE realm_name=$1 AND device_code_hash=$2`, realm, hash)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return storage.ErrNotFound
	}
	return nil
}

type sessionStore struct{ pool *pgxpool.Pool }

func (s *sessionStore) Create(ctx context.Context, sess storage.Session) error {
	_, err := s.pool.Exec(ctx,
		`INSERT INTO sessions (id_hash, realm_name, user_id, created_at, authenticated_at, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6)`,
		sess.IDHash, sess.RealmName, sess.UserID, sess.CreatedAt, sess.AuthenticatedAt, sess.ExpiresAt)
	return mapErr(err)
}

func (s *sessionStore) Get(ctx context.Context, realm, idHash string) (storage.Session, error) {
	var sess storage.Session
	err := s.pool.QueryRow(ctx,
		`SELECT id_hash, realm_name, user_id, created_at, authenticated_at, expires_at
		 FROM sessions WHERE realm_name=$1 AND id_hash=$2`, realm, idHash).Scan(
		&sess.IDHash, &sess.RealmName, &sess.UserID, &sess.CreatedAt, &sess.AuthenticatedAt, &sess.ExpiresAt)
	return sess, mapErr(err)
}

func (s *sessionStore) Delete(ctx context.Context, realm, idHash string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE realm_name=$1 AND id_hash=$2`, realm, idHash)
	return err
}

func (s *sessionStore) DeleteByUser(ctx context.Context, realm, userID string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM sessions WHERE realm_name=$1 AND user_id=$2`, realm, userID)
	return err
}

var _ storage.Store = (*Store)(nil)
var _ = pgx.ErrNoRows
