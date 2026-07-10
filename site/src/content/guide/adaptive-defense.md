---
title: Adaptive defense
chapter: 5
summary: sentinel — sliding-window limits, lockout that can't be weaponized, a deterministic risk pipeline, and a hash-chained audit log verified from two languages.
---

[sentinel](/projects/sentinel/) is the platform's decision service: every authentication attempt can be run through `POST /v1/check` and answered `allow | challenge | deny` — with a score and named reasons, never a bare verdict. The pipeline is three stages, each of which exists to demonstrate a specific defensive-engineering idea.

```
rate limit ──► lockout ──► risk score ──► decision ──► audit chain
(hard gate)   (hard gate)  (allow/challenge/deny)
```

## Rate limiting: the algorithm choice is the threat model

The requirements ([ADR 0001](https://github.com/aikazzh/portfolio/blob/main/sentinel/docs/adr/0001-sliding-window-counter.md)): O(1) memory per key across millions of keys, no boundary-burst artifact, an honest `Retry-After`, and state that maps onto Redis primitives for multi-instance sharing. Each rejected candidate fails one of these in an instructive way. Fixed windows admit 2× the limit around a boundary — unacceptable for a brute-force gate. A sliding log is exact but O(requests) per key, which means **an attacker inflates your memory by hammering you** — the defense inverted into a vulnerability. Token buckets are fine but need a Lua-wrapped read-modify-write and a second bucket for burst policy anyway.

The sliding-window counter keeps two integers per key (current + previous window) and estimates the effective count as `cur + prev × overlap_fraction`. Bounded error, and the state maps to Redis `INCR` + `EXPIRE` — the cheapest atomic primitives there are. Burst control is the same mechanism over a shorter window. Two honest details: `Retry-After` is computed by inverting the weighted formula rather than guessing, and denied requests still increment counters — hammering past your limit keeps you limited.

## Lockout that can't be turned against the victim

Brute-force lockout has a classic failure mode: anyone who knows a victim's username can fail five logins on purpose and lock them out — repeatedly, forever, for free. NIST SP 800-63B warns about exactly this. [ADR 0002](https://github.com/aikazzh/portfolio/blob/main/sentinel/docs/adr/0002-lockout-anti-dos.md)'s design tracks failures in two independent dimensions with **asymmetric caps**:

- **Per-account:** 5 failures → 1 minute, doubling, **capped at 15 minutes**.
- **Per-IP:** same escalation, **capped at 24 hours**.

The asymmetry is the point. The account dimension is attacker-controlled — unbounded escalation there converts lockout into a victim-DoS weapon, so the cap bounds the worst case at "victim inconvenienced", never "victim bricked", while still reducing online guessing to ~20 attempts/hour/account. The IP dimension only ever locks the attacker's own address, so it can escalate hard. Each dimension covers the other's blind spot: IP-only tracking misses a botnet focusing one victim; account-only tracking misses one host spraying many accounts.

The residual gap is documented, not hidden: a distributed attacker can re-lock one account at the cap indefinitely, and *longer lockouts make that worse, not better*. The fix is a different control — `Tracker.ChallengeHook` is the seam for switching repeat offenders to CAPTCHA/step-up/notify instead of more lockout. Two more properties from the [threat model](https://github.com/aikazzh/portfolio/blob/main/sentinel/THREAT_MODEL.md): a success landing during a lockout does not unlock (a stolen password isn't a free pass), and `Check` does identical work locked or not, because a distinguishable locked-account response is a username oracle.

## Risk: deterministic and explainable

The risk stage only chooses between allow/challenge/deny when both hard gates pass — it never lowers a gate's verdict. Signals are deterministic pure functions of (attempt, history): impossible travel via haversine distance, new-device detection, velocity, known-bad IPs. Determinism is a compliance feature: any decision can be replayed and explained from its audit record alone. Device fingerprints are only enrolled on *successful* auth, so an attacker can't whitelist a fingerprint by failing logins with it.

## The audit chain

Every decision lands in an append-only log where each record embeds the hash of everything before it ([ADR 0003](https://github.com/aikazzh/portfolio/blob/main/sentinel/docs/adr/0003-hash-chained-audit.md)):

```go
// hashRecord computes hex(SHA-256(prev hash hex || canonical JSON)).
h := sha256.New()
h.Write([]byte(r.Prev))
h.Write(c) // canonical JSON, hash field excluded
return hex.EncodeToString(h.Sum(nil)), nil
```

Why a chain and not the alternatives: per-record signatures detect modification but not deletion or reordering — a chain makes every record's validity depend on all history before it, and needs no key management. A Merkle tree earns its complexity when you need O(log n) inclusion proofs for third parties (certificate transparency); this log is verified by walking it end-to-end, which the compliance report does anyway.

The canonical form is the cross-language contract: compact JSON, sorted keys, HTML escaping off, all fields present, **string-only detail values** — because cross-language float formatting is where canonical-JSON schemes go to die. And the verification really is cross-language: the Go test suite executes the stdlib-only Python verifier against a Go-written chain, and the Python suite re-verifies a committed Go-generated fixture byte-for-byte. A compliance auditor can verify the chain with nothing but Python 3.

The honest limit is documented in the ADR itself: a hash chain is tamper-*evident* only against attackers who can't rewrite the whole file. Periodic anchor records — checkpoints of the chain head, themselves chained — are the mount point for the fix: push each anchor somewhere the log writer can't rewrite (a KMS-signed object in an S3 object-lock bucket, or an RFC 3161 timestamping authority). One externally trusted anchor then proves everything before it. The external push is a deployment integration, deliberately out of scope for now — infrastructure wiring, not a code change to sentinel.

## Reading list

[`audit/audit.go`](https://github.com/aikazzh/portfolio/blob/main/sentinel/audit/audit.go) — the canonical encoder and chain walker. [`tools/compliance/verify_chain.py`](https://github.com/aikazzh/portfolio/blob/main/sentinel/tools/compliance/verify_chain.py) — the independent verifier. [`lockout/`](https://github.com/aikazzh/portfolio/tree/main/sentinel/lockout) — the two-dimension tracker.

**Verified by:** 59 Go tests under `-race` plus 11 Python tests; `tools/compliance/report.py` re-verifies chain integrity before reporting and exits non-zero on a tampered log.
