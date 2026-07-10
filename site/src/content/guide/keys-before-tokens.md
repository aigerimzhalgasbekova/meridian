---
title: Keys before tokens
chapter: 2
summary: keysmith — four-state rotation with construction-time invariants, envelope encryption, and why the JOSE layer is hand-built.
---

Meridian's build order starts with [keysmith](/projects/keysmith/), not the authorization server. That's deliberate: every other service either asks keysmith to sign (idp) or verifies locally against its JWKS (everyone else). Building the key service first forces an honest interface — build the IdP first and key management becomes a retrofit shaped by whatever the IdP happened to need.

## Rotation as a state machine

Key rotation breaks systems in one specific way: a verifier receives a token signed by a key it hasn't learned yet (its JWKS cache predates the key), or a still-valid token outlives its key's publication. "Zero-downtime rotation" is exactly the elimination of those two windows.

keysmith's keys move through four states:

```
pending → active → retiring → retired
```

- **pending** — published in the JWKS, never signs. Minimum dwell before promotion.
- **active** — the unique signer per algorithm.
- **retiring** — demoted, still published for `RetireAfter`.
- **retired** — unpublished; ciphertext retained for audit.

A new key is *published before it ever signs*, and a demoted key *stays published until every token it signed has expired*. What makes this airtight rather than aspirational is that the two timing invariants are enforced at construction ([ADR 0003](https://github.com/aigerimzhalgasbekova/meridian/blob/main/keysmith/docs/adr/0003-rotation-state-machine.md)):

1. `JWKSMaxAge ≤ PendingDwell / 2` — every verifier cache must expire and refresh, picking up the pending key, before that key can start signing.
2. `MaxTokenTTL ≤ RetireAfter` — no token can outlive its key's publication window.

`service.New` refuses an unsafe configuration. The system fails at boot with a clear error instead of failing at 3am with a verification storm. The alternative — swap keys immediately and let verifiers error their way through a refresh stampede — is the common industry bug this project exists to demonstrate the fix for.

Everything is driven by an idempotent `Tick()`: cold-start bootstrap, pre-rotation generation, dwell-gated promotion, retirement — and one interesting recovery rule: if a pending key exists but no active key does, promote immediately, because an unsignable IdP is a worse failure than a cold cache. `Promote(force=true)` exists for key-compromise response, bypasses the dwell at a documented cost, and is audited.

## The JOSE layer: owning the protocol, not the crypto

The most questioned decision in the repo ([ADR 0001](https://github.com/aigerimzhalgasbekova/meridian/blob/main/keysmith/docs/adr/0001-minimal-jose-implementation.md)): keysmith implements JWS compact serialization, JWT claims validation, and JWK/JWKS handling itself — about 600 lines — instead of importing `go-jose` or `golang-jwt`.

"Don't roll your own crypto" applies to primitives, and no primitive is implemented here: signing and verification are one-call stdlib operations over `crypto/ed25519`, `crypto/ecdsa`, `crypto/rsa`. What the package owns is the *protocol* layer — parsing, serialization, policy — which is precisely where most real-world JWT vulnerabilities have lived: `alg: none` acceptance (CVE-2015-9235), RS256→HS256 key confusion (CVE-2016-5431, possible only because the library lets token input choose the algorithm family), embedded `jwk` header trust (CVE-2018-0114), `jku`/`x5u` dereference bugs.

Owning the layer deletes those degrees of freedom structurally. From [`jose/jws.go`](https://github.com/aigerimzhalgasbekova/meridian/blob/main/keysmith/jose/jws.go):

```go
dec := json.NewDecoder(strings.NewReader(string(rawHeader)))
dec.DisallowUnknownFields() // unknown header params are rejected, not ignored
if err := dec.Decode(&hdr); err != nil {
    return nil, zero, fmt.Errorf("%w: header not valid for this profile: %v",
        ErrHeaderRejected, err)
}
if len(hdr.Crit) > 0 || hdr.Jwk != nil || hdr.Jku != "" || hdr.X5u != "" || len(hdr.X5c) > 0 {
    return nil, zero, fmt.Errorf("%w: crit/jwk/jku/x5u/x5c are not accepted", ErrHeaderRejected)
}
```

Three asymmetric algorithms exist (EdDSA, ES256, RS256); HMAC does not; `none` does not. `kid` is mandatory, and the resolved key — never the token header — is the authority on which algorithm applies:

```go
key, err := resolver.VerificationKey(hdr.Kid)
...
if key.Alg != hdr.Alg {
    return nil, zero, fmt.Errorf("%w: token %q, key %q", ErrAlgMismatch, ...)
}
```

Each historical CVE class is a permanent regression test (`TestKnownAttackPatterns` in `jose/jws_test.go`). The trade-off is honest: ~600 lines of security-critical parsing to maintain, mitigated by a frozen surface. Interop is deliberately narrower than full JOSE — no JWE, no nested JWTs — and downstream services must live within this profile, which is the point.

## Envelope encryption with a KMS-shaped seam

Signing keys must survive restarts, so they're persisted — and a leaked keystore file must be useless. [ADR 0002](https://github.com/aigerimzhalgasbekova/meridian/blob/main/keysmith/docs/adr/0002-envelope-encryption.md) uses a two-level envelope: each private key is encrypted with its own random 256-bit DEK under AES-256-GCM, and only the DEK is wrapped by a KEK behind a two-method interface — `Wrap`/`Unwrap` — which is exactly the shape of a cloud KMS API. The local 32-byte master-key implementation is the dev posture; AWS KMS is a drop-in at deployment, and rotating the KEK re-wraps a few dozen bytes per key, never the key material.

The detail worth stealing: the GCM AAD binds each ciphertext to its key ID and algorithm. An attacker with file-write access who reorders records doesn't get key substitution — they get a detected integrity failure (`TestFileStoreTamperDetection`).

## Why this is project #1

The interface keysmith exports is small: sign, verify, JWKS, and a client library whose JWKS cache serves stale-if-error and force-refreshes once on an unknown `kid`. Every subsequent chapter leans on some part of it — idp delegates all signing to it, bridge reuses the `jose` package to verify *upstream* providers' tokens, console documents its production verifier as keysmith-JWKS-backed. Keys before tokens: get the foundation's contract right and the rest of the platform gets to treat cryptography as a solved dependency.

**Verified by:** 94 tests under `-race`, including the full rotation lifecycle on a fake clock, signing across a rotation boundary, restart mid-rotation on the encrypted store, and concurrent signing during rotation.
