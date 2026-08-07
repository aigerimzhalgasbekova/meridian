# Sentinel threat model

Sentinel is Meridian's adaptive-security decision service: rate limiting,
brute-force lockout, risk scoring, and the tamper-evident audit chain. It is
an **internal** service — its callers are other Meridian services (idp,
sessiond), never end users or the public internet.

## Assets

1. Decision integrity — an attacker who can flip deny→allow bypasses every
   control sentinel exists to provide.
2. The audit chain — the compliance evidence; its tamper-evidence is the
   product.
3. Lockout / rate-limit state — clearing it re-enables brute force.
4. Per-account risk history (devices, locations) — modest PII, and poisoning
   it blinds the risk signals.

## Trust boundaries

- HTTP surface (`/v1/*`): callers authenticate with a static bearer token
  compared in constant time. `/healthz` is the only unauthenticated route.
  Network exposure is expected to be cluster-internal (no public ingress).
- Audit file: writable only by the service; readable by compliance tooling.

## Threats and mitigations

### Spoofing / unauthorized callers
- Bearer token required on every `/v1` route; constant-time comparison
  prevents timing recovery. Server refuses to start without a token.
- Residual: one shared token means callers are mutually indistinguishable.
  Per-caller tokens or mTLS are a deployment upgrade; the auth middleware is
  the single seam.

### Tampering with the audit log
- Hash chain (ADR 0003): modification, deletion, or reordering breaks the
  first affected link; `GET /v1/audit/verify` and two independent verifiers
  (Go and Python) find it.
- Whole-file rewrite is detectable only via external anchoring: anchor
  records are the mount point for KMS/WORM/RFC 3161 notarization (documented,
  not wired — no cloud account in this environment).
- Residual, narrower than a whole-file rewrite: only the *last* anchor is
  cross-checked, so records after it are unvouched — an attacker with write
  access to the log can delete them and append fabricated ones, and both
  verifiers still report the chain intact. The window is `AnchorEvery`
  records wide (100 in production) and is now reported as
  `unvouched_records` / a "NOTE:" line rather than left silent. External
  anchoring closes it; nothing in-process can, because the chain is unkeyed
  and the sidecar shares the log's owner and mode.

### Denial of service
- **Against victims via lockout** — the signature abuse case. Account lockout
  is capped at 15m; unbounded escalation lives only in the attacker-owned IP
  dimension; ChallengeHook seam moves repeat offenses to CAPTCHA/step-up
  instead of longer locks (ADR 0002).
- **Against sentinel itself** — O(1) state per rate-limit key, amortized
  sweeping of stale keys, 1 MiB request-body cap, read/write timeouts.
  Residual: unbounded distinct-key cardinality from a spoofed-IP flood is
  bounded by the sweep but not eliminated; a Redis-backed store inherits
  Redis eviction.

### Bypassing the limiter / lockout
- Denied requests still count toward limits (no free retries).
- Success during an active lockout does not unlock — a stolen password does
  not convert a lockout into a free pass.
- Unknown rate-limit class is a hard error, not "unlimited" (typo-safe).

### Evading risk signals
- Device fingerprints are only trusted (enrolled) on successful auth —
  failing a login with a chosen fingerprint does not whitelist it.
- GeoIP gaps fail open for the travel signal only; the known-bad-IP and
  velocity signals still apply. Risk never *lowers* a hard gate's verdict.
- Signals are deterministic pure functions of (attempt, history), so any
  decision can be replayed and explained from the audit record.

### Information disclosure
- Lockout state must not become a username oracle: `Check` performs uniform
  work either way, and callers are directed (package doc) to return one
  uniform "invalid credentials" response.
- Audit records store IPs and account IDs — the minimum needed for the
  compliance mission; no credentials or tokens are ever logged.

## Out of scope

- TLS termination, network policy, and secret distribution (platform's job).
- Multi-instance state sharing (Redis seams documented in each package).
- Real GeoIP and threat-intel feeds (interfaces exist; fixtures ship).
