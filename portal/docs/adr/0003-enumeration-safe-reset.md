# ADR 0003: Enumeration-safe password reset

**Status:** Accepted · 2026-07-09

## Context

`POST /api/auth/forgot` takes an email address. If its behavior differs for
existing vs. unknown accounts — status code, body, or response time — the
endpoint becomes an oracle for harvesting valid user emails (a real finding in
most pentests, and a GDPR-relevant disclosure).

## Decision

The endpoint behaves identically on both paths:

1. **Identical response:** `202 {"ok":true}` whether or not the account exists.
   The UI says "if an account exists, a link is on its way."
2. **Uniform timing:** the handler runs under `withMinDuration(100ms)` — it
   never responds faster than the floor, masking the work difference between
   "look up, generate token, enqueue email" and "look up, stop".
3. **Asynchronous email:** the send happens in the job queue after the response,
   so SMTP latency can't leak through the HTTP round-trip either.

Token design, on the success path:

- 256-bit random, sent by email once, stored **only** as a SHA-256 hash — a
  database leak exposes no usable tokens.
- 15-minute TTL, single use. `markUsed` is an atomic compare-and-set
  (`WHERE used_at IS NULL`), so a double-submitted token wins exactly once.
- Redeeming a token revokes the user's other outstanding reset tokens and
  deletes **all** sessions — a reset ends any attacker's live session.
- Lookup is by hash with a constant-time comparison helper; login verifies a
  decoy Argon2 hash for unknown accounts so password checks are also
  timing-uniform.

## Rationale

The minimum-duration floor is deliberately chosen over "constant-time
everything": it is a few lines, testable (the suite asserts both paths meet the
floor and return byte-identical bodies), and needs no tuning.

Its limit is worth stating plainly, because it was originally overstated here:
the floor is `max(floor, work)`, not a fixed budget. It only masks a branch
whose work stays *under* it. Signup's account-new branch runs Argon2id
(m=19456, t=2), which on the deployed 0.25 vCPU task overruns 100 ms under
concurrent load while the taken-address branch does not — so the branches
separate again. The fix is not a bigger floor but symmetric work: both signup
branches now hash a password. Any expensive step added to one side of one of
these handlers and not the other reopens the oracle.

## Consequences

- Every forgot-password request costs ~100 ms latency. Irrelevant for a human
  flow.
- Rate limiting still matters (the endpoint sends email); the in-memory
  limiter covers a single node, `sentinel` is the distributed seam.
- Signup returns `202` on both branches and mails the address owner a reset
  link when the address is taken, so it does not leak by status code. It is
  still an existence oracle in two requests: the taken branch never applies the
  submitted password, so signing up with a chosen password and then logging in
  with it distinguishes free (`200`) from taken (`401`). Accepted — standard
  UX, its abuse case is covered by rate limiting, and closing it requires an
  email-first signup flow out of scope here.
- Redeeming a reset token also clears any pending email change and revokes its
  verification token. Reset is the documented remedy for a compromised account,
  so it has to revoke the capabilities an attacker extracted, not just their
  sessions.
