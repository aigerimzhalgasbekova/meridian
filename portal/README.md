# portal — self-service identity portal

Account lifecycle flows a real IdP needs but that rarely get engineering care:
password reset, email verification and change, TOTP MFA enrollment, and session
management — all driven by a Postgres-backed job queue for asynchronous email.

Part of the [Meridian platform](../docs/design/2026-07-09-meridian-platform-design.md).
TypeScript throughout: Express API + polling job worker, React/Vite frontend.

## What it showcases

- **Enumeration-safe password reset** — identical response body *and* a minimum
  response duration whether or not the account exists; 15-minute single-use
  tokens stored only as SHA-256 hashes; using one revokes its siblings and
  invalidates every session. ([ADR 0003](docs/adr/0003-enumeration-safe-reset.md))
- **Email change that can't lock you out** — the old address stays the login
  until the new one proves it can receive mail.
- **Hand-rolled RFC 6238 TOTP** — HMAC-SHA1 over `node:crypto`, verified
  against the RFC's Appendix B test vectors; ±1 step drift window; replay
  defense (an accepted time-step can never be accepted again); 10 single-use
  recovery codes shown once and stored hashed. ([ADR 0002](docs/adr/0002-hand-rolled-totp.md))
- **Postgres as a job queue** — `SELECT … FOR UPDATE SKIP LOCKED` claiming,
  exponential backoff, dead-lettering, owned claims that expire (so a crashed
  worker's job is reclaimed without a startup requeue that would steal a live
  one from the second worker every rolling deploy). The in-memory
  implementation mirrors the claim semantics exactly, so the whole pipeline is
  tested without a database. ([ADR 0001](docs/adr/0001-postgres-job-queue.md))
- **Boring, correct session auth** — httpOnly SameSite=Lax cookies (hashed
  server-side), double-submit CSRF header on mutations, TOTP step-up at login,
  per-IP rate limiting on auth endpoints.

## Layout

```
server/           Express API, job worker, repositories
  src/app.ts        all HTTP routes
  src/crypto/       TOTP, base32, Argon2id passwords, opaque tokens
  src/queue/        queue interface + memory & postgres impls, polling worker
  src/store/        repository interface + memory & postgres impls
  src/mail/         transport seam: outbox files (dev), memory (test); SES/SMTP later
  test/             vitest + supertest suites
  schema.sql        full Postgres schema
web/              React + Vite frontend (hand-rolled CSS, no router/library)
```

## Run it

```sh
npm install
npm run dev        # API on :3000 (in-memory store), web on :5173
```

Sign up at <http://localhost:5173>. "Emails" are JSON files written to
`server/outbox/` — the server log prints a preview path for each one; copy the
link out of the file to complete verification / reset flows.

Against Postgres — `PORTAL_TOTP_KEK` becomes mandatory here, because the
in-code placeholder key must never protect a real database:

Re-applying `schema.sql` also lower-cases `users.email` and adds the check
constraint that keeps it that way. If the backfill trips the unique index, two
accounts differ only by case: keep one, migrate its data, delete the other,
re-run. It also adds `jobs.claimed_at` and widens the claim index on existing
installs; rows already `running` keep a null `claimed_at` and are reaped via
`COALESCE(claimed_at, run_at)`, so nothing is stranded mid-upgrade.

```sh
psql "$DATABASE_URL" -f server/schema.sql
DATABASE_URL=postgres://… \
PORTAL_TOTP_KEK=$(openssl rand -base64 32) \
  npm run dev -w server
```

## Test

```sh
npm test                                    # no database needed
TEST_DATABASE_URL=postgres://… npm test     # also runs pg integration tests
```

The Postgres suite (store round-trips, queue claim/backoff/dead-letter, real
SKIP LOCKED concurrency) is skipped when `TEST_DATABASE_URL` is unset.

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | API port |
| `DATABASE_URL` | *(unset — in-memory)* | Postgres store + queue |
| `PORTAL_TOTP_KEK` | *(placeholder; required once `DATABASE_URL` is set)* | 32-byte base64 key sealing TOTP secrets at rest |
| `OUTBOX_DIR` | `./outbox` | Where dev mail files are written |
| `BASE_URL` | `http://localhost:5173` | Origin used in emailed links |
| `WEB_DIST` | `./web/dist` | Built SPA; served when the directory exists |
| `NODE_ENV` | — | `development` drops `Secure` from cookies; secure by default otherwise |

## Seams left for the platform

- **Mail:** `MailTransport` is one method; production drops in an SES (or SMTP)
  implementation. Idempotency does *not* come free with it: today it is the dev
  outbox overwriting `outbox/<job-id>.json`, so a real transport must carry its
  own (see [ADR 0001](docs/adr/0001-postgres-job-queue.md)) or a retry is a
  second token-bearing email.
- **Rate limiting:** the in-memory fixed-window limiter is per-process; the
  platform's `sentinel` decision API replaces that middleware for distributed
  limiting.

See also [THREAT_MODEL.md](THREAT_MODEL.md).
