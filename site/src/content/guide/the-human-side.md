---
title: The human side
chapter: 7
summary: portal — enumeration-safe recovery flows, TOTP from the RFC up, and Postgres as a job queue.
---

Password reset, email change, MFA enrollment: the flows that rarely get engineering care, and the ones attackers actually target — account recovery is the standard way around a strong password. [portal](/projects/portal/) gives them the care, in TypeScript end to end: an Express API, a polling job worker, and a React frontend.

## Enumeration-safe by construction

`POST /api/auth/forgot` takes an email address. If its behavior differs for existing vs. unknown accounts — status, body, or *response time* — it becomes an oracle for harvesting valid emails: a real finding in most pentests and a GDPR-relevant disclosure. [ADR 0003](https://github.com/aigerimzhalgasbekova/meridian/blob/main/portal/docs/adr/0003-enumeration-safe-reset.md) makes the two paths identical three ways:

1. **Identical response:** `202 {"ok":true}` either way.
2. **Uniform timing:** the handler runs under `withMinDuration(100ms)` — it never responds faster than the floor, masking the work difference between "look up, generate token, enqueue email" and "look up, stop".
3. **Asynchronous email:** the send happens in the job queue *after* the response, so SMTP latency can't leak through the HTTP round-trip either.

The floor is a deliberate choice over "constant-time everything": it's a few lines, it's testable — the suite asserts both paths meet the floor and return byte-identical bodies — and it's robust to future work being added to either path. Jitter adds noise; a floor gives a guarantee.

The token side: 256-bit random, emailed once, stored only as a SHA-256 hash, 15-minute TTL, single-use via an atomic compare-and-set (`WHERE used_at IS NULL` — a double-submitted token wins exactly once). Redeeming one revokes the user's other outstanding reset tokens and deletes **all** sessions, so a reset ends any attacker's live session. Login gets the same timing discipline: unknown users are verified against a decoy Argon2 hash.

One honest exception, documented in the ADR: signup's 409-on-duplicate *is* an existence oracle, kept for standard UX and covered by rate limiting. Security posture includes knowing which oracles you've chosen to keep.

## TOTP from the RFC up

MFA enrollment uses TOTP — implemented directly on `node:crypto`, about 60 lines, rather than an npm package ([ADR 0002](https://github.com/aigerimzhalgasbekova/meridian/blob/main/portal/docs/adr/0002-hand-rolled-totp.md)). The algorithm is small and frozen (one HMAC, a dynamic-truncation offset, a modulus; unchanged since 2011), the npm options are a poor trade (`speakeasy` unmaintained since 2017, `otplib` a dependency tree for one screen of code), and the RFCs publish test vectors that make correctness objective — the suite pins every one of RFC 4226 Appendix D and RFC 6238 Appendix B.

The core, from [`totp.ts`](https://github.com/aigerimzhalgasbekova/meridian/blob/main/portal/server/src/crypto/totp.ts):

```ts
export function hotp(secret: Buffer, counter: bigint, digits = TOTP_DIGITS, algorithm = 'sha1'): string {
  const msg = Buffer.alloc(8);
  msg.writeBigUInt64BE(counter);
  const mac = createHmac(algorithm, secret).update(msg).digest();
  const offset = mac[mac.length - 1]! & 0x0f;
  const code = (((mac[offset]! & 0x7f) << 24) | ((mac[offset + 1]! & 0xff) << 16) |
      ((mac[offset + 2]! & 0xff) << 8) | (mac[offset + 3]! & 0xff)) % 10 ** digits;
  return code.toString().padStart(digits, '0');
}
```

The ADR's real argument: **the hard parts are policy, not math, and libraries don't solve them.** `verifyTotp` returns the *matched time-step counter*, not a boolean, because replay defense means persisting the last accepted counter and rejecting anything ≤ it — even within the ±1-step drift window an authenticator app needs. Enrollment is verify-to-activate (a wrong-device enrollment can't lock you out), codes are compared with `timingSafeEqual`, and ten single-use recovery codes are shown once and stored hashed. All of that lives in application code whichever library you pick.

## Postgres as a job queue

Verification and reset emails are sent asynchronously, which needs a durable queue with retries and dead-lettering. The conventional reflex is Redis (BullMQ) or SQS. [ADR 0001](https://github.com/aigerimzhalgasbekova/meridian/blob/main/portal/docs/adr/0001-postgres-job-queue.md): portal already has Postgres — an external queue adds an infrastructure component, a client library, a failure mode, a local-dev story, and the dual-write problem, to move a handful of emails per minute.

Instead: a `jobs` table claimed with `SELECT … FOR UPDATE SKIP LOCKED` — the textbook mechanism for competing consumers on a relational queue; concurrent workers each lock a different row with no advisory locks and no contention loops. Exponential backoff (1s·4ⁿ, capped at 5 minutes), `max_attempts`, then a `dead` status as the parking lot. The ceiling is stated rather than discovered later: row-claim queues degrade around thousands of jobs/second from table bloat and vacuum pressure; portal is orders of magnitude below, handlers are idempotent, and the `JobQueue` interface is five methods if a broker swap ever earns its keep.

The testing move worth copying: the in-memory queue mirrors the claim semantics *exactly* — selection and status-flip in one synchronous step, the clock passed in rather than read ambiently — so retry, backoff, dead-lettering, and two-worker exclusivity are tested without a database, and the identical suite runs against real Postgres when `TEST_DATABASE_URL` is set. (The clock-as-argument rule was learned the hard way; the story is in [chapter 10](/guide/lessons-learned/).)

One threat-model item that's easy to miss: job payloads embed the emailed link, raw token included, so the `jobs` table and the dev outbox directory are secret-bearing — dead-lettered rows should be purged, not archived. It's in the [threat model](https://github.com/aigerimzhalgasbekova/meridian/blob/main/portal/THREAT_MODEL.md) because that's where operational footguns belong.

**Verified by:** `npm test` — 50 tests pass, 3 skipped (the Postgres integration suite, which runs when `TEST_DATABASE_URL` is set). The 22 TOTP tests include every published RFC vector; the 20 API tests drive the full HTTP flows, including asserting the enumeration-safe paths return byte-identical bodies above the timing floor.
