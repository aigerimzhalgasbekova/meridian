-- Meridian idp Postgres schema.
--
-- Secrets are stored hashed (see the storage package doc). Money-shot columns:
-- auth_codes.used + issued_family_id enable replay revocation; refresh_tokens
-- rotated_at + family_id + revoked enable reuse detection and family kill.

CREATE TABLE IF NOT EXISTS realms (
    name              TEXT PRIMARY KEY,
    display_name      TEXT NOT NULL,
    access_token_ttl  BIGINT NOT NULL,   -- nanoseconds
    refresh_token_ttl BIGINT NOT NULL,
    session_ttl       BIGINT NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS clients (
    realm_name    TEXT NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    client_id     TEXT NOT NULL,
    secret_hash   BYTEA,
    name          TEXT NOT NULL,
    redirect_uris TEXT[] NOT NULL DEFAULT '{}',
    grant_types   TEXT[] NOT NULL DEFAULT '{}',
    public        BOOLEAN NOT NULL DEFAULT FALSE,
    first_party   BOOLEAN NOT NULL DEFAULT FALSE,
    scopes        TEXT[] NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (realm_name, client_id)
);

CREATE TABLE IF NOT EXISTS users (
    id             TEXT NOT NULL,
    realm_name     TEXT NOT NULL REFERENCES realms(name) ON DELETE CASCADE,
    username       TEXT NOT NULL,
    email          TEXT NOT NULL DEFAULT '',
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    password_hash  TEXT NOT NULL DEFAULT '',
    name           TEXT NOT NULL DEFAULT '',
    given_name     TEXT NOT NULL DEFAULT '',
    family_name    TEXT NOT NULL DEFAULT '',
    disabled       BOOLEAN NOT NULL DEFAULT FALSE,
    created_at     TIMESTAMPTZ NOT NULL,
    updated_at     TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (realm_name, id)
);
-- Case-insensitive username uniqueness. A table-level UNIQUE constraint cannot
-- contain an expression like lower(), so this must be a unique index.
CREATE UNIQUE INDEX IF NOT EXISTS users_realm_username ON users (realm_name, lower(username));

CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash        TEXT NOT NULL,
    realm_name       TEXT NOT NULL,
    client_id        TEXT NOT NULL,
    user_id          TEXT NOT NULL,
    redirect_uri     TEXT NOT NULL,
    scopes           TEXT[] NOT NULL DEFAULT '{}',
    nonce            TEXT NOT NULL DEFAULT '',
    code_challenge   TEXT NOT NULL DEFAULT '',
    auth_time        TIMESTAMPTZ NOT NULL,
    session_id       TEXT NOT NULL DEFAULT '',
    used             BOOLEAN NOT NULL DEFAULT FALSE,
    issued_family_id TEXT NOT NULL DEFAULT '',
    expires_at       TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (realm_name, code_hash)
);
CREATE INDEX IF NOT EXISTS auth_codes_expiry ON auth_codes (expires_at);
-- auth_codes was originally keyed on code_hash alone, which let any realm's
-- token endpoint consume (and thereby burn) another realm's code before the
-- application-level realm check ran. Realm-scope the key like every other
-- table. Existing rows keep their values; the constraint is only rebuilt when
-- the current primary key is still single-column, so this is a no-op after the
-- first run.
DO $$
BEGIN
    IF (SELECT indnatts FROM pg_index WHERE indrelid = 'auth_codes'::regclass AND indisprimary) = 1 THEN
        ALTER TABLE auth_codes DROP CONSTRAINT auth_codes_pkey;
        ALTER TABLE auth_codes ADD PRIMARY KEY (realm_name, code_hash);
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT NOT NULL,
    realm_name TEXT NOT NULL,
    family_id  TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    scopes     TEXT[] NOT NULL DEFAULT '{}',
    auth_time  TIMESTAMPTZ NOT NULL,
    nonce      TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    rotated_at TIMESTAMPTZ,
    revoked    BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (realm_name, token_hash)
);
CREATE INDEX IF NOT EXISTS refresh_tokens_family ON refresh_tokens (realm_name, family_id);

CREATE TABLE IF NOT EXISTS consents (
    realm_name TEXT NOT NULL,
    user_id    TEXT NOT NULL,
    client_id  TEXT NOT NULL,
    scopes     TEXT[] NOT NULL DEFAULT '{}',
    granted_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (realm_name, user_id, client_id)
);

CREATE TABLE IF NOT EXISTS device_codes (
    device_code_hash TEXT NOT NULL,
    realm_name       TEXT NOT NULL,
    user_code        TEXT NOT NULL,
    client_id        TEXT NOT NULL,
    scopes           TEXT[] NOT NULL DEFAULT '{}',
    status           TEXT NOT NULL,
    user_id          TEXT NOT NULL DEFAULT '',
    -- When the approving user last actively authenticated. NULL until
    -- approval, and on rows approved before this column existed.
    auth_time        TIMESTAMPTZ,
    interval_secs    INT NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL,
    last_polled_at   TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (realm_name, device_code_hash),
    UNIQUE (realm_name, user_code)
);
ALTER TABLE device_codes ADD COLUMN IF NOT EXISTS auth_time TIMESTAMPTZ;

CREATE TABLE IF NOT EXISTS sessions (
    id_hash          TEXT NOT NULL,
    realm_name       TEXT NOT NULL,
    user_id          TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL,
    authenticated_at TIMESTAMPTZ NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (realm_name, id_hash)
);
CREATE INDEX IF NOT EXISTS sessions_user ON sessions (realm_name, user_id);
