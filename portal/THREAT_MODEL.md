# portal Threat Model

Scope: the self-service portal — signup/login, password reset, email
verification and change, TOTP enrollment and step-up, session management, and
the email job pipeline.

## Assets

| Asset | Impact if compromised |
|-------|----------------------|
| Password hashes (Argon2id) | Account takeover after offline cracking |
| Session cookies | Impersonation for the session lifetime |
| Reset / verification tokens | Account takeover (reset), address hijack (verify) |
| TOTP secrets | Second factor defeated |
| Recovery codes | Second factor defeated |
| Email pipeline | Phishing from a trusted sender, token exfiltration |

## Trust boundaries

1. **Browser ↔ API.** Untrusted user agent. Defenses: httpOnly SameSite=Lax
   cookies; double-submit CSRF header on every mutation; per-IP rate limiting
   on auth endpoints; input validation on all bodies.
2. **Email ↔ user's inbox.** Delivery is outside our control. Tokens are the
   only secret that crosses this boundary: 256-bit, single-use, short-lived,
   and stored server-side only as hashes.
3. **API ↔ database.** Parameterized queries throughout; no secret material
   stored raw (session ids, tokens, recovery codes all hashed; TOTP secrets
   necessarily stored recoverable — see residual risks).

## Key defenses by flow

**Login.** Unknown-user and wrong-password responses are identical, and the
unknown path verifies a decoy Argon2 hash so timing matches. TOTP-enrolled
accounts get an `mfa_pending` session that cannot use any authenticated
endpoint until the step-up passes.

**Password reset.** Enumeration-safe (identical body + minimum-duration
response, ADR 0003). 15-minute single-use hashed tokens; redeeming one revokes
siblings and destroys every session.

**Email change.** The old address remains the login until the new address
proves receipt. Requesting a new change revokes prior pending tokens; a
superseded token is rejected. Duplicate-address checks at request *and*
confirm time.

**TOTP.** Verify-to-activate (a wrong-device enrollment can't lock you out).
±1 step drift only. Replay defense: the last accepted time-step counter is
persisted and anything ≤ it is rejected, even within the drift window. Codes
compared with `timingSafeEqual`. Recovery codes: 10, single-use, hashed,
displayed exactly once.

**Sessions.** Cookie value is 256-bit random; only its SHA-256 is stored, so a
database leak yields no usable cookies. Users can list and revoke their own
sessions only; expiry enforced server-side.

**Job queue.** Handlers are idempotent (mail keyed by job id) so retries never
double-send a token email. Job payloads embed the emailed link — raw token
included — so the `jobs` table (and the dev outbox directory) must be treated
as secret-bearing: dead-lettered rows should be purged, not archived.

## Residual risks / accepted

- **TOTP secrets stored unencrypted at rest.** Verification requires the raw
  secret. Envelope encryption via keysmith is the platform upgrade path.
- **In-memory rate limiting is per-process.** Multi-node deployments need the
  `sentinel` decision API (documented seam); until then a distributed attacker
  faces only per-node limits.
- **Signup reveals account existence** (409 on duplicate). Accepted for UX;
  see ADR 0003.
- **No account lockout / breach-password screening.** Rate limiting plus
  Argon2id is the current posture; both are additive later.
- **Email is a recovery channel.** Whoever controls the inbox can reset the
  password. TOTP step-up is deliberately *not* bypassed by reset — but reset
  does not disable TOTP either, so inbox compromise alone is insufficient for
  enrolled accounts.
