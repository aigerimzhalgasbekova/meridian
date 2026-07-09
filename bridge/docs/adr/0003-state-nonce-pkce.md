# ADR 0003: State, nonce, and PKCE design for the RP flow

## Status

Accepted.

## Context

The RP side of the authorization-code flow has three anti-forgery values with
distinct jobs, commonly confused with each other:

- **state** binds the callback to a login this RP actually started (CSRF /
  session-fixation defense on the redirect).
- **nonce** binds the *ID token* to this login (token replay/injection
  defense — it travels inside the signed token).
- **PKCE verifier** binds the *code redemption* to the party that initiated
  authorization (code interception defense).

Each value must be one-time, unpredictable, and — for the verifier
especially — never exposed in URLs.

## Decision

`internal/relay` keeps a server-side flow record per login attempt and derives
everything from it:

- **State parameter** = base64url(JSON{flow id, provider, exp}) `.`
  HMAC-SHA256 signature. The signature makes state unforgeable (an attacker
  cannot mint one our callback accepts), the embedded expiry bounds the window
  (10 minutes), and the provider binding stops a state minted for
  `/callback/google` being replayed to `/callback/entra`.
- **One-time use by consumption, not by signature.** Verifying a state
  atomically deletes its flow record; a second presentation — attacker
  replaying a captured URL, or a user double-clicking — finds nothing and is
  rejected. A signature check alone can never provide replay protection
  (signatures verify as many times as you like); server-side state can. Both
  exist because they defend against different things.
- **Nonce and PKCE verifier live only in the server-side record.** The state
  parameter transits the upstream's URLs, logs, browser history, and Referer
  headers; the code verifier is the proof-of-possession the exchange depends
  on and must not. Both are 32 bytes of CSPRNG output; the 43-char base64url
  verifier is a valid RFC 7636 verifier, and only its S256 challenge goes
  upstream (`plain` is never offered).
- **Check order in `Consume`:** signature first (until it passes, every
  payload byte is attacker-controlled), then expiry, then one-time use. The
  callback handler deliberately collapses all three failures into one uniform
  user-facing message; the distinct errors exist for logs.
- Expired flows are swept opportunistically on each `Begin` — no background
  goroutine to leak.

## Alternatives considered

- **Stateless (encrypted-cookie) flows.** Attractive for multi-node, but
  one-time use then needs a shared replay cache anyway, which is the same
  server-side state through the back door. In-memory records are honest about
  the requirement; a shared store slots in when bridge goes multi-node.
- **Random-blob state with pure server lookup (no HMAC).** Workable, but the
  HMAC lets the callback reject garbage before touching the store and carries
  the provider binding and expiry even if the record is gone, which yields
  precise log lines for replay attempts.
