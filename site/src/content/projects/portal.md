---
name: portal
title: portal
pitch: The self-service identity portal — password reset, email change, TOTP MFA, and session management over a Postgres job queue.
challenge: Async workflow security — the account-lifecycle flows that rarely get engineering care, enumeration-safe and driven by FOR UPDATE SKIP LOCKED.
tech: [TypeScript, Node, Express, React, Postgres]
order: 6
---

## What it is

Account lifecycle flows a real IdP needs: password reset, email verification and change, TOTP MFA enrollment with recovery codes, and session management — all driven by a Postgres-backed job queue for asynchronous email. TypeScript throughout: Express API + polling job worker, React/Vite frontend with hand-rolled CSS.

## Key design decisions

- **[ADR 0001 — Postgres as the job queue.](https://github.com/aikazzh/portfolio/blob/main/portal/docs/adr/0001-postgres-job-queue.md)** Portal already has Postgres; Redis or SQS would add an infrastructure component, a client library, and a dual-write problem to move a handful of emails per minute. `SELECT … FOR UPDATE SKIP LOCKED` is the textbook competing-consumers mechanism, with exponential backoff (1s·4ⁿ capped at 5 min) and a `dead` status as the dead-letter parking lot. The known ceiling (thousands of jobs/second) is documented, and the in-memory implementation mirrors the claim semantics exactly so the whole pipeline is tested without a database.
- **[ADR 0002 — hand-rolled RFC 6238 TOTP.](https://github.com/aikazzh/portfolio/blob/main/portal/docs/adr/0002-hand-rolled-totp.md)** ~60 lines on `node:crypto`, verified against the RFC test vectors. The npm alternatives are a poor trade (`speakeasy` unmaintained since 2017; `otplib` pulls a dependency tree for one screen of auditable code) — and the hard parts are policy, not math, and live in application code either way: ±1-step drift window, replay defense (the last accepted time-step counter is persisted; anything ≤ it is rejected *even within the drift window*), verify-to-activate enrollment, hashed single-use recovery codes.
- **[ADR 0003 — enumeration-safe reset.](https://github.com/aikazzh/portfolio/blob/main/portal/docs/adr/0003-enumeration-safe-reset.md)** `POST /api/auth/forgot` returns an identical `202` body whether or not the account exists, under a `withMinDuration(100ms)` floor — deliberately chosen over "constant-time everything" because a floor is a few lines, testable, and robust to future work on either path. The email send happens in the job queue *after* the response, so SMTP latency can't leak either. Reset tokens: 256-bit, hashed at rest, 15-minute single-use; redemption revokes sibling tokens and destroys every session.

## Security highlights

From the [threat model](https://github.com/aikazzh/portfolio/blob/main/portal/THREAT_MODEL.md): unknown-user login verifies a decoy Argon2 hash so timing matches; TOTP-enrolled accounts get an `mfa_pending` session that can't use any authenticated endpoint until step-up passes; email change keeps the old address as the login until the new one proves receipt; session cookies are 256-bit random with only the SHA-256 stored; job payloads embed emailed links (raw token included), so the jobs table and dev outbox are documented as secret-bearing. Honest residuals: TOTP secrets are necessarily stored recoverable (keysmith envelope encryption is the platform upgrade path), and signup's 409-on-duplicate intentionally remains an existence oracle — standard UX, covered by rate limiting.

## Verified by

- `npm test` — **50 tests pass, 3 skipped** (run 2026-07-10; the 3 skipped are the Postgres integration suite, which runs when `TEST_DATABASE_URL` is set — store round-trips, queue claim/backoff/dead-letter, real SKIP LOCKED concurrency).
- TOTP is pinned to the RFC 4226 Appendix D and RFC 6238 Appendix B published vectors (`test/totp.test.ts`, 22 tests).
- The API suite (20 tests) drives full HTTP flows: enumeration-safe reset (asserting both paths meet the timing floor and return byte-identical bodies), enrollment + step-up, email change, session revocation.

## Code worth reading

- [`server/src/crypto/totp.ts`](https://github.com/aikazzh/portfolio/blob/main/portal/server/src/crypto/totp.ts) — HOTP/TOTP in one screen, returning the matched counter so callers can enforce replay defense.
- [`server/src/queue/`](https://github.com/aikazzh/portfolio/tree/main/portal/server/src/queue) — the queue interface, the Postgres `SKIP LOCKED` implementation, and the memory twin that mirrors its claim semantics.
- [`server/src/app.ts`](https://github.com/aikazzh/portfolio/blob/main/portal/server/src/app.ts) — every HTTP route in one navigable file.
