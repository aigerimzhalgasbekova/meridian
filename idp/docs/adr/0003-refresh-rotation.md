# ADR 0003: Refresh-token rotation with family-based reuse detection

**Status:** Accepted · 2026-07-09

## Context

Refresh tokens are long-lived credentials. If one leaks, the attacker can mint
access tokens until it expires. We need to detect and contain leakage.

## Decision

Refresh tokens are opaque 256-bit random values, stored only as SHA-256 hashes,
and **rotated on every use**: each successful refresh invalidates the presented
token and issues a new one. All generations descended from one authorization
share a `family_id`. Presenting a token that has already been rotated — the
signature of a leaked-and-replayed token — **revokes the entire family**.

The same treatment applies to three other theft-shaped events: a token
presented by the wrong client, a token whose owning user is disabled, and two
concurrent redemptions of the same token (the loser of the atomic rotation).

Absolute family lifetime is fixed at first issuance and inherited across every
rotation — rotating never extends it (tested in `token_test.go`).

## Rationale

Rotation alone isn't enough: without reuse detection, a stolen token that the
attacker uses *before* the legitimate client just silently takes over the
family. Family revocation turns any reuse into a detectable, contained event —
the legitimate client's next refresh fails, signalling the compromise, and no
tokens from that family remain valid. This is the RFC 9700 §4.14 recommendation.

Atomicity is essential and is delegated to the store: the Postgres `Rotate` is a
single conditional `UPDATE ... WHERE rotated_at IS NULL` inside a transaction, so
the database row lock guarantees exactly one winner even across replicas. The
concurrency test fires 12 simultaneous redemptions of one token and asserts at
most one succeeds and the family dies.

## Consequences

- A legitimate client that races itself (e.g. two tabs) can trip reuse
  detection and get logged out. This is the accepted, standard trade-off; it is
  rare and fails safe (toward revocation, not toward token survival).
- Access tokens remain stateless JWTs and are *not* revocable individually;
  their containment is their short TTL (≤ keysmith's retire window). Revocation
  operates on refresh families. `/revoke` answers `unsupported_token_type` for
  an access token rather than lying with a 200.
