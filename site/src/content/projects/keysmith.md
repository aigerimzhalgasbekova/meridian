---
name: keysmith
title: keysmith
pitch: Cryptographic key lifecycle as a service — zero-downtime rotation, envelope encryption, and a hardened minimal JOSE layer.
challenge: Rotating signing keys without ever breaking a verifier, with the safety invariants proven at construction time instead of hoped for at 3am.
tech: [Go, stdlib crypto, JOSE, AES-GCM]
order: 1
---

## What it is

KeySmith owns signing keys for the whole platform. Every other Meridian service either asks it to sign (idp) or verifies locally against its JWKS (everyone else). It ships as a daemon (`cmd/keysmithd`), a Go client with a stale-tolerant JWKS cache, and — the part other projects import directly — a zero-dependency `jose` package.

## The architectural challenge

Key rotation breaks systems in one specific way: a verifier receives a token signed by a key it hasn't learned yet, or a still-valid token outlives its key's publication. KeySmith eliminates both windows with a four-state machine — `pending → active → retiring → retired` — where a key is **published before it ever signs** and **stays published until every token it signed has expired**.

The two timing invariants that make this airtight are validated at service construction, not documented and hoped for:

- `JWKSMaxAge ≤ PendingDwell / 2` — every verifier cache must refresh (picking up the pending key) before that key can start signing.
- `MaxTokenTTL ≤ RetireAfter` — no token can outlive its key's publication window.

An unsafe configuration fails to boot. See [ADR 0003 — rotation state machine](https://github.com/aikazzh/portfolio/blob/main/keysmith/docs/adr/0003-rotation-state-machine.md).

## Key design decisions

- **[ADR 0001 — minimal JOSE instead of a library.](https://github.com/aikazzh/portfolio/blob/main/keysmith/docs/adr/0001-minimal-jose-implementation.md)** ~600 lines of protocol plumbing over stdlib crypto only. "Don't roll your own crypto" applies to primitives, not to the parsing-and-policy layer where most real JWT CVEs have actually lived. Owning the layer deletes the vulnerable degrees of freedom structurally: no `alg: none`, no HMAC (so no RS256→HS256 confusion), no `jwk`/`jku`/`x5u`/`crit`, unknown header parameters rejected, and the pinned key set — never the token — decides the algorithm.
- **[ADR 0002 — envelope encryption.](https://github.com/aikazzh/portfolio/blob/main/keysmith/docs/adr/0002-envelope-encryption.md)** Per-key AES-256-GCM DEKs wrapped by a two-method KEK interface (`Wrap`/`Unwrap`) — exactly the shape of a cloud KMS API, so the production KMS-backed KEK is a drop-in. GCM AAD binds each ciphertext to its key ID and algorithm, so an attacker shuffling records in the keystore file produces integrity failures, not key confusion.
- **[ADR 0003 — the rotation machine](https://github.com/aikazzh/portfolio/blob/main/keysmith/docs/adr/0003-rotation-state-machine.md)** is driven by an idempotent `Tick()`: cold-start bootstrap, availability recovery, pre-rotation generation, dwell-gated promotion, retirement. `Promote(force=true)` exists for key-compromise response and is audited.

## Security highlights

From the [threat model](https://github.com/aikazzh/portfolio/blob/main/keysmith/THREAT_MODEL.md): the JWKS endpoint is public and carries no secrets; signer and admin tokens are separate classes compared in constant time; `exp`/`iat` are server-set with a TTL cap so a stolen signer token cannot mint long-lived tokens; `/v1/verify` returns coarse reasons only so verification errors can't become a forgery oracle; private-JWK serialization does not exist in the codebase (tested). Accepted residual risks — LocalKEK in process memory, single-writer file store, no HSM — are documented rather than hidden.

## Verified by

- `go test -race ./...` — **94 tests pass** (run 2026-07-10 on this repo, no Docker).
- Every historical JOSE attack class is a permanent regression test: `jose/jws_test.go: TestKnownAttackPatterns`.
- Full rotation lifecycle against a fake clock; signing across a rotation boundary; restart mid-rotation on the encrypted store; concurrent signing during rotation under `-race`; KEK-mismatch and ciphertext-shuffling tamper cases; timing-safe auth boundaries.

## Code worth reading

- [`jose/jws.go`](https://github.com/aikazzh/portfolio/blob/main/keysmith/jose/jws.go) — `Verify` and its strict, non-negotiable header policy (`DisallowUnknownFields`, hard rejection of `crit`/`jwk`/`jku`/`x5u`/`x5c`, key set as the algorithm authority).
- [`keystore/`](https://github.com/aikazzh/portfolio/tree/main/keysmith/keystore) — the lifecycle manager and envelope encryption.
- [`client/`](https://github.com/aikazzh/portfolio/tree/main/keysmith/client) — the verifier-side JWKS cache with stale-if-error behavior and kid-miss refresh.
