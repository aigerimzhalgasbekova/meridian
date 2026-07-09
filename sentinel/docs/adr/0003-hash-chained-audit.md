# ADR 0003: Hash-chained audit log with periodic anchors

**Status:** Accepted · 2026-07-09

## Context

Compliance-grade audit logs must be tamper-evident: an attacker (or insider)
who gains write access to the log store must not be able to silently modify,
delete, or reorder history. Candidates: signed individual records, a Merkle
tree, or a hash chain.

## Decision

Hash chain: each record stores `hash = SHA-256(prev_hash_hex || canonical
JSON of the record)`. Every `AnchorEvery` records, an anchor record
checkpointing the current chain head (seq + hash) is appended, itself
chained. Canonical JSON is compact, keys sorted, HTML escaping off, all
fields present, string-only detail values.

## Rationale

- **Chain vs. per-record signatures:** signing each record detects
  modification but not deletion or reordering; a chain makes every record's
  validity depend on all history before it, so any edit breaks every
  subsequent link. Signatures also demand key management for a property the
  chain gives for free.
- **Chain vs. Merkle tree:** Merkle trees earn their complexity when you need
  O(log n) inclusion proofs for third parties (certificate transparency).
  This log is verified by walking it end-to-end — which the compliance report
  does anyway — so a chain is the same guarantee with a tenth of the code.
- **Canonical form is the contract.** The exact bytes are specified so the
  Python verifier (`tools/compliance/verify_chain.py`) reimplements them
  independently; the Go test suite runs the Python verifier against a
  Go-written chain to prove byte-level agreement. String-only detail values
  exist because cross-language float formatting is where canonical-JSON
  schemes go to die.
- **Anchors and the honest limit:** a hash chain alone is tamper-*evident*
  only against attackers who cannot rewrite the whole file — full rewrite +
  rehash is undetectable from the inside. Anchors are the fix's mount point:
  in production each anchor hash is also pushed somewhere the log writer
  cannot rewrite — a KMS-signed object in an S3 object-lock (WORM) bucket, or
  an RFC 3161 timestamping authority. One externally trusted anchor then
  proves the integrity of everything before it. The external push is a
  deployment integration, deliberately out of scope here; the anchor records
  and their placement are in.

## Consequences

- Verification is O(n) over the log; fine for service-lifetime logs, and the
  `Store` interface documents the streaming-verification seam for a
  Postgres-backed store.
- The log is append-only by construction; log rotation must cut over to a new
  chain whose genesis references the old head (operational runbook item).
