# ADR 0003: Four-state rotation machine with published-before-signing dwell

**Status:** Accepted · 2026-07-09

## Context

Key rotation breaks systems in one specific way: a verifier receives a token
signed by a key it hasn't learned yet (its JWKS cache predates the key), or a
still-valid token outlives its key's publication. "Zero-downtime rotation" is
exactly the elimination of those two windows.

## Decision

Keys move through `pending → active → retiring → retired`:

- **pending** — published in the JWKS, never signs. Minimum dwell before
  promotion: `PendingDwell`.
- **active** — the unique signer per algorithm.
- **retiring** — demoted, still published for `RetireAfter`.
- **retired** — unpublished; ciphertext retained for audit.

Two cross-component timing invariants are *enforced at construction*, not
documented and hoped for:

1. `JWKSMaxAge ≤ PendingDwell / 2` — every verifier cache must expire and
   refresh (picking up the pending key) before that key can start signing.
   (`service.New` refuses the config otherwise.)
2. `MaxTokenTTL ≤ RetireAfter` — no token can outlive its key's publication
   window. (Also refused at construction.)

`Tick()` drives everything periodically and is idempotent: cold-start
bootstrap, availability recovery (pending exists, active missing → promote
immediately: an unsignable IdP is a worse failure than a cold cache),
pre-rotation generation, dwell-gated promotion, retirement. Manual
`Promote(force=true)` exists for key-compromise response and is audited.

## Rationale

The alternative — rotate by immediately swapping keys and letting verifiers
417 their way through a refresh storm — is the common industry bug this
project exists to demonstrate the fix for. Encoding the timing invariants as
constructor errors makes the safety property hold by configuration-time proof
rather than runtime luck. The client library closes the last gap (a verifier
that slept through the dwell) with a single forced re-fetch on unknown `kid`.

## Consequences

- Rotation latency is bounded below by `PendingDwell`; emergency rotation
  bypasses it with `force` at the documented cost of possible verification
  misses until caches refresh (mitigated by the client's kid-miss refresh).
- One active key per algorithm keeps the model simple; multi-region
  active/active signing would require relaxing this and is out of scope.
