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
floor and return byte-identical bodies), and robust to future work being added
to either path. Per-request jitter adds noise but not a guarantee; a floor
gives one.

## Consequences

- Every forgot-password request costs ~100 ms latency. Irrelevant for a human
  flow.
- Rate limiting still matters (the endpoint sends email); the in-memory
  limiter covers a single node, `sentinel` is the distributed seam.
- Signup (`409` on duplicate) intentionally remains an existence oracle —
  standard UX; its abuse case is covered by rate limiting, and closing it
  requires an email-first signup flow out of scope here.
