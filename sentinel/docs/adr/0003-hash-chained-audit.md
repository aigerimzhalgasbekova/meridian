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
- The log is append-only and grows without bound. Retention is a policy, not a
  feature you can bolt on with `logrotate` — see below.

## Retention and rotation policy

The chain is tamper-*evident* precisely because removing any record breaks
verification. That property and naive retention are in direct conflict: you
cannot free space by deleting old records, because `verify_chain.py` will (by
design) then report `BROKEN`. Deleting the oldest lines leaves the new first
record's `prev` pointing at a hash no longer in the file (chain-walk failure);
deleting a middle span opens a sequence gap; truncating the tail is caught by
the anchor sidecar. Every removal mode is detected — that is the point, and
`TestRetentionFrontTruncationDetected` pins it.

So retention MUST preserve verifiability. Operational rules, in order of
preference:

1. **Archive, never truncate in place.** When the active log is large, copy the
   whole `sentinel-audit.jsonl` (and its `.anchors` sidecar) to WORM/cold
   storage, then start a *new* chain file. Keep the archived files verifiable:
   an auditor concatenates archive + live and runs `verify_chain.py` over the
   whole thing. Nothing is deleted from a live chain.
2. **Roll by sealing, not cutting.** To start a fresh file whose size resets,
   record the sealed file's head (seq + hash) as the genesis reference of the
   next file. The prior agent's out-of-band anchor sidecar already captures
   every head hash, so a sealed segment's head is durably recorded off-file;
   the sidecar makes the boundary explicit and any later gap detectable rather
   than silent.
3. **Pruning requires accounting.** Only sealed, externally-anchored, archived
   segments may be pruned from hot storage. Their head hashes remain in the
   `.anchors` sidecar and in the WORM archive, so a pruned segment's absence is
   provable, not silent. Never prune a segment whose head is not anchored
   out-of-band.

Explicitly **not** implemented (YAGNI at current volume): automatic
multi-segment rotation with a prune sweeper, and a `verify_chain.py` that walks
across segment boundaries accepting an anchored non-genesis start. Add these
only when log volume actually forces rotation; until then the sidecar +
archive-don't-truncate rules above are sufficient and cannot silently lose
history. The invariant to preserve if that feature is ever built:
`verify_chain.py` must never print `OK` for a log whose records were removed
without a corresponding anchor accounting for them.
