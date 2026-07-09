# ADR 0001: Opaque random tokens, not JWTs, for browser sessions

**Status:** Accepted · 2026-07-09

## Context

Meridian already has a JWT pipeline (keysmith signs, everyone verifies
locally). The tempting move is to reuse it for browser sessions: issue a
signed token, validate statelessly, skip the Redis dependency.

## Decision

Sessions are 256-bit random opaque tokens. Redis stores only the SHA-256 of
the token, keyed by that hash; the raw token exists only in the holder's
cookie and in the create/rotate response, exactly once.

## Rationale

Every hard requirement of a session system is a statement about *server-side
state*:

- **Logout / logout-everywhere** means destroying state now, not waiting for
  `exp`. A JWT revocation list that must be checked on every request *is* a
  session store — with a signature bolted on top that no longer buys anything.
- **Concurrent-session limits** require counting live sessions per user, which
  requires an index, which requires state.
- **Sliding idle expiry** requires recording last-seen, which requires a write
  per touch.

Once the state exists, the JWT's one advantage (stateless validation)
evaporates and its costs remain: attacker-readable claims, a signing-key
dependency in the critical auth path, and revocation always lagging.

Hashing the stored token is the part that earns its keep: session stores are
a classic bearer-credential trove, and SHA-256 turns a Redis snapshot, a
replication-stream tap, or a read-only compromise into a pile of
unpresentable digests. The hash also serves as the session ID for admin
surfaces (list, revoke-by-id), so admin operations never handle presentable
credentials at all. Unsalted SHA-256 is sufficient — the preimage is 256 bits
of CSPRNG output, so brute force is out of reach and rainbow tables have no
structure to exploit.

## Consequences

- Validation costs a Redis round trip; a bounded per-node cache (ADR 0003)
  amortizes it without giving up revocation guarantees.
- Redis availability gates session validation. Acceptable: Redis is already
  the platform's session point of truth, and nodes fail closed.
- Tokens cannot carry claims. Correct: claims belong in the identity layer
  (idp), and callers get metadata (user, realm, timestamps) from validate.
