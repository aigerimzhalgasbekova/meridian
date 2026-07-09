# ADR 0002: Envelope encryption for private keys at rest

**Status:** Accepted · 2026-07-09

## Context

Signing keys must survive process restarts, so they must be persisted. A leaked
keystore file must be useless to an attacker.

## Decision

Two-level envelope scheme:

1. Each private key (PKCS#8) is encrypted with its own random 256-bit **DEK**
   using AES-256-GCM. The GCM AAD binds the ciphertext to `key ID + algorithm`,
   so records cannot be transplanted between key slots undetected.
2. Only the DEK is wrapped by a **KEK** behind a two-method interface
   (`Wrap`/`Unwrap`). Implementations: `LocalKEK` (32-byte master key from
   configuration) now; AWS KMS in the platform deployment (the interface is
   the seam — swapping wrappers never touches key-material code).

Records store the KEK ID; opening a store with the wrong KEK fails closed,
even before AEAD verification (and AEAD verification also fails, tested with
a same-ID imposter KEK).

## Rationale

- **Blast-radius control:** rotating or migrating the KEK re-wraps DEKs — a
  few dozen bytes each — never the key material itself.
- **KMS-shaped by construction:** cloud KMS APIs *are* Wrap/Unwrap. Designing
  for that seam locally means the production path (KMS-backed KEK, master key
  never in application memory) is a drop-in.
- **AAD over metadata** turns "attacker with file write access reorders
  records" from a key-substitution attack into a detected integrity failure
  (tested: `TestFileStoreTamperDetection`).

## Consequences

- `LocalKEK`'s master key lives in process memory and in the deployment's
  secret store; this is the accepted dev/single-node posture and is called out
  in the threat model. Production posture is the KMS KEK.
- The file store is single-writer by design (atomic temp+rename, fsync).
  Multi-node keysmith would need a database store and a rotation leader —
  documented as an explicit non-goal for this deployment size.
