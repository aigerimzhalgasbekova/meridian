# sentinel

Adaptive security and compliance service for the Meridian IAM platform:
distributed rate limiting, brute-force lockout, risk scoring, and a
tamper-evident (hash-chained) audit log — plus Python compliance tooling that
verifies the chain independently of the Go code.

## Signature challenge

High-throughput stream decisions with a compliance-grade paper trail. Every
`/v1/check` answer is explainable (score + named reasons) and lands in an
append-only hash chain that a stdlib-Python auditor can verify without Go,
sentinel, or network access.

## Architecture

```
POST /v1/check ──► rate limit (per-IP / per-user / per-client, sliding window)
                   └► lockout (per-account AND per-IP, escalating, capped)
                       └► risk score 0–100 (travel, device, velocity, bad IPs)
                           └► allow | challenge | deny  ──► audit chain (JSONL)
```

| Package | What it proves |
|---|---|
| `ratelimit` | Sliding-window counter, O(1)/key, burst + sustained, honest Retry-After ([ADR 0001](docs/adr/0001-sliding-window-counter.md)) |
| `lockout` | Two-dimension escalating lockout that cannot be weaponized as victim-DoS ([ADR 0002](docs/adr/0002-lockout-anti-dos.md)) |
| `risk` | Deterministic pluggable signal pipeline: impossible travel (haversine), new device, velocity, known-bad IPs |
| `audit` | Hash-chained append-only log with anchors; JSONL + in-memory stores ([ADR 0003](docs/adr/0003-hash-chained-audit.md)) |
| `internal/server` | stdlib `net/http` service; constant-time bearer auth |
| `tools/compliance` | Python (stdlib-only) chain verifier + markdown compliance report |

All state is in-memory behind narrow interfaces; each package documents its
Redis/Postgres seam. No frameworks, no external dependencies.

## API

All `/v1` routes require `Authorization: Bearer $SENTINEL_TOKEN`.

| Route | Purpose |
|---|---|
| `POST /v1/check` | Decide an attempt: `{account, ip, client_id?, device_id?}` → `{decision: allow\|challenge\|deny, score, reasons, retry_after_seconds?}` |
| `POST /v1/report-auth-result` | Feed back an outcome: `{account, ip, device_id?, success}` — drives lockout counters and risk history |
| `POST /v1/events` | Append an arbitrary event to the audit chain |
| `GET /v1/audit/verify` | Walk the chain; report the first broken link |
| `GET /healthz` | Liveness (no auth) |

Rate limit and lockout are hard gates (deny + `Retry-After`); risk chooses
between allow / challenge / deny only when both gates pass. Every decision is
audited.

## Run

```sh
make run-dev        # SENTINEL_TOKEN=dev-token, in-memory audit, :8084
make build          # bin/sentineld
```

Environment: `SENTINEL_ADDR`, `SENTINEL_TOKEN` (required),
`SENTINEL_AUDIT_PATH` (JSONL file, or `memory`), `SENTINEL_BAD_IPS`.

## Test

```sh
make test           # go test -race ./...
make test-py        # python3 -m unittest discover tools/compliance
make report         # sample compliance report from the bundled fixture
```

Cross-language proof: `audit`'s Go tests run `verify_chain.py` against a
Go-written chain, and the Python suite re-verifies a Go-generated fixture
byte-for-byte (`tools/compliance/testdata/sample_audit.jsonl`).

## Compliance tooling

Both tools expect the log's out-of-band anchor sidecar, `audit.jsonl.anchors`,
beside it. Verification is two halves and needs both: the hash chain catches
modification, reordering, and gaps, while the sidecar catches *truncation* —
a log with its tail lopped off is a valid prefix of a valid chain, so the walk
alone reports it intact. A missing sidecar fails closed, because deleting it
is exactly what an attacker who truncated the log would do.

```sh
python3 tools/compliance/verify_chain.py audit.jsonl   # exit 0 = intact
python3 tools/compliance/report.py audit.jsonl [out.md]
```

The report covers decision breakdown, failure trends, lockouts, and risky IPs.
It runs the same two-part verification first and exits non-zero on a tampered
log. Pass `--allow-missing-anchors` to either tool only for logs written
before the sidecar existed — never for a live one.

## Docs

- [THREAT_MODEL.md](THREAT_MODEL.md)
- [ADR 0001 — sliding-window counter](docs/adr/0001-sliding-window-counter.md)
- [ADR 0002 — lockout anti-DoS](docs/adr/0002-lockout-anti-dos.md)
- [ADR 0003 — hash-chained audit](docs/adr/0003-hash-chained-audit.md)
