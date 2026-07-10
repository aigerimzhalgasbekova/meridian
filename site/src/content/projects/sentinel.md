---
name: sentinel
title: sentinel
pitch: Adaptive security decisions — distributed rate limiting, lockout, risk scoring, and a tamper-evident audit chain verified in two languages.
challenge: High-throughput stream decisions with a compliance-grade paper trail — every answer explainable, every event in a hash chain a stdlib-Python auditor can verify without Go.
tech: [Go, Python, hash chain, sliding window]
order: 4
---

## What it is

Meridian's adaptive-security decision service. `POST /v1/check` runs an attempt through three stages — rate limit (per-IP / per-user / per-client), brute-force lockout (per-account *and* per-IP), and a deterministic risk pipeline (impossible travel, new device, velocity, known-bad IPs) — and answers `allow | challenge | deny` with a score and named reasons. Every decision lands in an append-only, hash-chained audit log; Python tooling verifies the chain and renders compliance reports independently of the Go code.

## Key design decisions

- **[ADR 0001 — sliding-window counter.](https://github.com/aikazzh/portfolio/blob/main/sentinel/docs/adr/0001-sliding-window-counter.md)** Two fixed-window counters per key (current + previous), effective count = `cur + prev × overlap`. O(1) memory per key (a sliding log lets attackers inflate your memory — inverting the defense), no fixed-window boundary burst, and state that maps onto Redis `INCR`/`EXPIRE`. `Retry-After` is computed honestly by inverting the weighted formula, and denied requests still count.
- **[ADR 0002 — lockout that can't be weaponized.](https://github.com/aikazzh/portfolio/blob/main/sentinel/docs/adr/0002-lockout-anti-dos.md)** Classic lockout hands attackers a DoS primitive against victims. Sentinel escalates in two dimensions with asymmetric caps: per-account capped at **15 minutes** (that dimension is attacker-controlled — the cap bounds the worst case at "inconvenienced", never "bricked", while reducing online guessing to ~20 attempts/hour), per-IP capped at 24 hours (escalation there only ever locks the attacker's own address).
- **[ADR 0003 — hash chain, not signatures, not a Merkle tree.](https://github.com/aikazzh/portfolio/blob/main/sentinel/docs/adr/0003-hash-chained-audit.md)** Each record stores `hash = SHA-256(prev_hash_hex || canonical JSON)`. Per-record signatures detect modification but not deletion or reordering; a Merkle tree earns its complexity only when you need O(log n) inclusion proofs. Canonical JSON is the cross-language contract — compact, keys sorted, HTML escaping off, string-only detail values, "because cross-language float formatting is where canonical-JSON schemes go to die."

```go
// hashRecord computes hex(SHA-256(prev hash hex || canonical JSON)).
func hashRecord(r Record) (string, error) {
    c, err := canonical(r)
    if err != nil {
        return "", err
    }
    h := sha256.New()
    h.Write([]byte(r.Prev))
    h.Write(c)
    return hex.EncodeToString(h.Sum(nil)), nil
}
```

## Security highlights

From the [threat model](https://github.com/aikazzh/portfolio/blob/main/sentinel/THREAT_MODEL.md): success during an active lockout does not unlock — a stolen password doesn't convert a lockout into a free pass; an unknown rate-limit class is a hard error, not "unlimited" (typo-safe); device fingerprints are only enrolled on *successful* auth, so failing logins with a chosen fingerprint can't whitelist it; `Check` performs uniform work whether or not a key is locked, so lockout state can't become a username oracle; risk never lowers a hard gate's verdict. The honest limit of hash chains is documented too: whole-file rewrite is only detectable via external anchoring, and the periodic anchor records are the mount point for KMS/WORM/RFC 3161 notarization.

## Verified by

- `go test -race ./...` — **59 tests pass**; `python3 -m unittest discover tools/compliance` — **11 tests pass** (both run 2026-07-10).
- Cross-language proof: the Go audit tests execute `verify_chain.py` against a Go-written chain, and the Python suite re-verifies a Go-generated fixture byte-for-byte (`tools/compliance/testdata/sample_audit.jsonl`).
- `tools/compliance/report.py` re-verifies chain integrity before reporting and exits non-zero on a tampered log.

## Code worth reading

- [`audit/audit.go`](https://github.com/aikazzh/portfolio/blob/main/sentinel/audit/audit.go) — canonical JSON and the chain (`canonical`, `hashRecord`, `Append`, `VerifyChain`).
- [`tools/compliance/verify_chain.py`](https://github.com/aikazzh/portfolio/blob/main/sentinel/tools/compliance/verify_chain.py) — the independent stdlib-Python verifier.
- [`lockout/`](https://github.com/aikazzh/portfolio/tree/main/sentinel/lockout) — the two-dimension escalating tracker and its `ChallengeHook` seam.
