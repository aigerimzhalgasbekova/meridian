# ADR 0002: Envelope encryption for private keys at rest

**Status:** Accepted · 2026-07-09

## Context

Signing keys must survive process restarts, so they must be persisted. A leaked
keystore file must be useless to an attacker.

## Decision

Two-level envelope scheme:

1. Each private key (PKCS#8) is encrypted with its own random 256-bit **DEK**
   using AES-256-GCM. The GCM AAD binds the ciphertext to `key ID + algorithm`
   *and to the record's lifecycle position* — state, all four timestamps, and
   the document generation the record was written in — so transplanting a
   record between key slots, editing the plaintext metadata, and replaying an
   authentic record from an earlier write all fail closed. Document version 1
   bound only `id + algorithm`, leaving the lifecycle forgeable; a v1 document
   is still accepted on read (verified under the v1 AAD) and rewritten at v2 on
   the start that reads it. Back-compat on read, upgrade on write: no opt-in
   variable, no operator step, no way to brick the platform's only signer on
   deploy. The residual downgrade path is in the threat model.
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
  (tested: `TestFileStoreTamperDetection`). Extending it over the lifecycle
  fields closes the other half: the thumbprint check proves the key *material*
  is genuine, and only the AAD proves its *position* is (tested:
  `TestFileStoreLifecycleTamperRejected`). Without it, resurrecting a retired
  key as the active signer needed no KEK at all.

## Consequences

- `LocalKEK`'s master key lives in process memory and in the deployment's
  secret store; this is the accepted dev/single-node posture and is called out
  in the threat model. Production posture is the KMS KEK.
- The file store is single-writer *by enforcement*, not by convention: an
  exclusive advisory lock on `<store>.lock` is held for the process lifetime,
  so a second writer fails to start instead of silently replaying its stale
  whole-document snapshot. The lock sits beside the keystore rather than on it
  because `persist` renames a new file over the path. Deployments must roll
  with stop-before-start.
- Writes are atomic (temp file + rename) and fsynced on *both* halves — the
  temp file's contents and the containing directory's entry. Syncing only the
  file, the common version of this idiom, leaves a write reported durable that
  a power loss can still take back.
  Multi-node keysmith would need a database store and a rotation leader —
  documented as an explicit non-goal for this deployment size.
