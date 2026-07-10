-- portal schema. Apply with: psql "$DATABASE_URL" -f schema.sql

CREATE TABLE IF NOT EXISTS users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               TEXT NOT NULL UNIQUE,
    email_verified      BOOLEAN NOT NULL DEFAULT FALSE,
    pending_email       TEXT,
    password_hash       TEXT NOT NULL,
    totp_secret         TEXT,           -- base32; set only after verify-to-activate
    totp_pending_secret TEXT,           -- enrollment in progress
    totp_last_counter   TEXT,           -- last accepted time-step (replay defense)
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS sessions (
    id_hash    TEXT PRIMARY KEY,        -- SHA-256 of the cookie value; raw ids never stored
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    mfa_pending BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_user_idx ON sessions (user_id);

CREATE TABLE IF NOT EXISTS one_time_tokens (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose    TEXT NOT NULL CHECK (purpose IN ('password_reset', 'verify_email')),
    token_hash TEXT NOT NULL UNIQUE,    -- SHA-256; raw tokens never stored
    payload    TEXT,                    -- verify_email: the address being verified
    expires_at TIMESTAMPTZ NOT NULL,
    used_at    TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ott_user_purpose_idx ON one_time_tokens (user_id, purpose) WHERE used_at IS NULL;

CREATE TABLE IF NOT EXISTS recovery_codes (
    user_id   UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,            -- SHA-256; shown to the user exactly once
    used_at   TIMESTAMPTZ,
    PRIMARY KEY (user_id, code_hash)
);

-- Job queue: workers claim with SELECT ... FOR UPDATE SKIP LOCKED.
CREATE TABLE IF NOT EXISTS jobs (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    type         TEXT NOT NULL,
    payload      JSONB NOT NULL DEFAULT '{}',
    status       TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'done', 'dead')),
    attempts     INTEGER NOT NULL DEFAULT 0,
    max_attempts INTEGER NOT NULL DEFAULT 5,
    run_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_error   TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS jobs_claim_idx ON jobs (run_at, created_at) WHERE status = 'pending';
