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
   necessarily reversible, so sealed under a KEK — see residual risks).

## Key defenses by flow

**Login.** Unknown-user and wrong-password responses are identical, and the
unknown path verifies a decoy Argon2 hash so timing matches. TOTP-enrolled
accounts get an `mfa_pending` session that cannot use any authenticated
endpoint until the step-up passes.

**Password reset.** Enumeration-safe (identical body + minimum-duration
response, ADR 0003). 15-minute single-use hashed tokens; redeeming one revokes
siblings, destroys every session, *and* cancels any pending email change with
its outstanding verification token — a change queued by an attacker who held a
session would otherwise still flip the login address 24 h later, since
`verify-email` is authorized by the token alone.

**Email change.** The login address is treated as a credential, not a profile
field, because it is the root of every mailed recovery path: `/api/account/email`
re-verifies the account password, so a stolen cookie alone cannot move it and
then simply ask `/forgot` for a new one. The old address remains the login until
the new address proves receipt. Requesting a new change revokes prior pending
tokens; a superseded token is rejected. Duplicate-address checks at request *and*
confirm time. Confirming a change mails the address it moved *away from* a
notification — no link, no token. A token that restored the address would be a
full account-recovery capability (restore, `/forgot` there, `/reset`) mailed to
an address the account has just stopped using and may never have proved receipt
of at all: a signup typo of a stranger's address, corrected later, would hand
that stranger the account. The move is announced, not reversible in-product.

**TOTP.** Verify-to-activate (a wrong-device enrollment can't lock you out).
±1 step drift only. Replay defense: the last accepted time-step counter is
persisted and anything ≤ it is rejected, even within the drift window. Codes
compared with `timingSafeEqual`. Recovery codes: 10, single-use, hashed,
displayed exactly once, count surfaced on `/api/me` so the last one is not
spent unnoticed. Enrolling, disabling, and regenerating codes all re-verify the
account password — a stolen session cookie alone cannot enroll an attacker's
authenticator, which reset deliberately does not undo. That property only holds
because `/api/account/email` re-authenticates too: a cookie that could move the
login address would reach the password in three more calls (verify, forgot,
reset). Disabling additionally
requires a fully stepped-up session, so it is not an MFA bypass for a password
holder. That password check does nothing against an attacker who *knows* the
password (stuffing, phishing), so activation also mails the account address a
notice carrying a single-use `undo_totp` token (24 h): redeeming it clears the
factor, the recovery codes and every session. It is the only exit that works
once an attacker has enrolled — reset does not clear TOTP and `/totp/disable`
needs a session that already stepped up — and it grants an inbox-only attacker
nothing, since revoking a factor is never satisfying one.

**Sessions.** Cookie value is 256-bit random; only its SHA-256 is stored, so a
database leak yields no usable cookies. Users can list and revoke their own
sessions only; expiry enforced server-side.

**Job queue.** A claim is owned: `complete`/`fail` write a terminal state only
while `claimed_at` still matches the claim they came from — not merely while the
job is `running`, which a reaped job is again — and a job is reclaimable only
once its claim is 5 minutes stale, with reaps spending attempts so a handler
that always outlives the window dead-letters instead of being redelivered
forever. So the two overlapping workers of a rolling deploy cannot
resurrect each other's finished jobs. Job payloads embed the emailed link — raw
token included — so the `jobs` table (and the dev outbox directory) must be
treated as secret-bearing: dead-lettered rows should be purged, not archived.

## Residual risks / accepted

- **TOTP secrets are recoverable by whoever holds the KEK.** Verification
  requires the raw secret, so the database stores it sealed (AES-256-GCM under
  `PORTAL_TOTP_KEK`) rather than hashed. A database dump alone yields nothing;
  a dump plus the process environment yields every second factor. Moving the
  KEK into keysmith-managed KMS, so the key never sits beside the ciphertext,
  is the platform upgrade path.
- **In-memory rate limiting is per-process.** Multi-node deployments need the
  `sentinel` decision API (documented seam); until then a distributed attacker
  faces only per-node limits.
- **Signup still reveals account existence, in two requests.** It returns
  `202` on both branches (no 409 — the docs claimed one long after the code
  stopped emitting it) and mails the address owner a reset link when the
  address is taken. But the taken branch never applies the submitted password,
  so `signup{target, chosen}` followed by `login{target, chosen}` answers the
  question: `200` means the address was free, `401` means it was taken.
  Accepted; closing it needs an email-first signup flow, out of scope here.
  Note also that `withMinDuration` is a floor, not a fixed budget — it only
  masks a branch whose work stays under it, which is why both signup branches
  now pay the Argon2 cost explicitly. Anything expensive added to one branch
  and not the other reopens a timing oracle.
- **Duplicate-address responses elsewhere are oracles too** (`409` from
  `/api/account/email`, at request and at confirm time). Kept for real UX
  value, but rate-limited like the auth routes rather than left unthrottled.
- **No account lockout / breach-password screening.** Rate limiting plus
  Argon2id is the current posture; both are additive later. The limiter buckets
  on the *matched route*, not `req.path`, or case and trailing-slash variants
  of the same URL would each get their own budget.
- **Email is a recovery channel.** Whoever controls the inbox can reset the
  password. TOTP step-up is deliberately *not* bypassed by reset — reset does
  not disable TOTP. The exit is `POST /api/security/totp/disable`, which needs
  the password *and* a session that already passed the step-up. The inbox alone
  clears a second factor in exactly one window: the single-use `undo_totp` link
  mailed when that factor is enabled, expiring 24 h later. The uncovered case is
  therefore a lost authenticator, all ten recovery codes spent, and that window
  long gone: unrecoverable in-product by design, since any standing escape hatch
  is a standing MFA bypass. An out-of-band identity-proofed support path is the
  upgrade.
- **An attacker who knows the password can still move the login address away.**
  Password re-auth on `/api/account/email` stops a stolen cookie, not a stuffed
  or phished password. Once the change is confirmed the old address is told, but
  it has no in-product way back: everything downstream (`/forgot`, `undo_totp`)
  is addressed to the new inbox. The counterweight tried in the previous
  revision — an undo token mailed to the old address — was worse than the
  attack it answered, because that inbox is not proven to belong to the account
  either. Recovery here is the same out-of-band identity-proofed path as a lost
  authenticator.
