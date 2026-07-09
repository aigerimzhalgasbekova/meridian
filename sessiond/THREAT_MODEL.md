# sessiond Threat Model

Scope: the sessiond service, its Redis store, the pub/sub invalidation
channel, and the trust relationships with calling services (idp, portal) and
the demo browser surface.

## Assets

| Asset | Impact if compromised |
|-------|----------------------|
| Live session tokens (in flight / in cookies) | Attacker acts as the user until revocation or expiry |
| Redis session store contents | SHA-256 hashes only — not presentable; metadata (user, realm, IP, UA hash) leaks activity patterns |
| Service API tokens | Attacker mints, lists, and revokes sessions for arbitrary users |
| Redis write access | Attacker forges session records for chosen users — full session-layer compromise |
| Pub/sub channel (publish) | Attacker can only *revoke* (deny service); cannot extend or forge |

## Trust boundaries

1. **Services → /v1 API.** Bearer tokens; both sides hashed then compared in
   constant time with uniform iteration over all configured tokens. No tokens
   configured ⇒ API fails closed (503), never open.
2. **Browsers → /demo.** HttpOnly, SameSite=Lax, path-scoped cookie; CSP
   `default-src 'none'`; demo credentials are fixtures — real authentication
   lives in idp.
3. **sessiond → Redis.** Redis is inside the trust perimeter (network-isolated
   in deployment). Token hashing is defense in depth for *read* paths
   (snapshots, backups, replication taps), not a defense against Redis write
   access.
4. **Node → node (pub/sub).** Fire-and-forget by design; correctness never
   depends on delivery (ADR 0003).

## Top abuse cases and mitigations

| # | Attack | Mitigation |
|---|--------|-----------|
| 1 | Token guessing / brute force | 256-bit CSPRNG tokens; search space is not meaningfully enumerable |
| 2 | Session store exfiltration (snapshot, backup, read-only compromise) | Only SHA-256 hashes stored; unsalted is sufficient against 256-bit random preimages |
| 3 | Session fixation (attacker seeds a victim's session) | Rotate API: new ID minted server-side, old ID atomically dead in the same Lua script; demo login always revokes any pre-login session and mints fresh |
| 4 | Stolen token used forever | Sliding idle TTL and absolute lifetime cap; cap re-checked inside the touch script so no touch sequence and no stale Redis TTL extends it |
| 5 | Revoked session kept alive by a node's cache | Bounded staleness: entries live ≤ CacheTTL (2s default); pub/sub makes it near-instant; missed broadcast cannot exceed the bound; tested with a node that never subscribes |
| 6 | Session-flood DoS on one account | Per-user cap enforced atomically at create; evict-oldest (default) or reject policy |
| 7 | Racing the cap from two nodes | Create-under-cap is one Lua script; hammer test drives two nodes in parallel under `-race` and asserts the cap held |
| 8 | Validity oracle (probing which sessions exist) | Missing/expired/revoked are one indistinguishable 404; revoke is idempotent 204; list/revoke-all require the service token anyway |
| 9 | Timing oracle on API token comparison | SHA-256 both sides + `subtle.ConstantTimeCompare`, no early break across tokens |
| 10 | Key/field injection via realm or user ID | `[A-Za-z0-9._-]{1,64}` allowlist before any value is spliced into a Redis key |
| 11 | Rotation replay (old token after rotate) | Old key deleted in the same script that writes the new one; no interleaving window; revocation broadcast |
| 12 | Demo CSRF (forced logout / rotate) | SameSite=Lax cookie; state-changing demo routes are POST-only. Accepted as demo-grade: no double-submit token |
| 13 | Raw user agent strings as stored PII | Only a truncated SHA-256 fingerprint is stored |
| 14 | Panic → information leak | Recovery middleware returns opaque 500; details to structured logs only |

## Residual risks (accepted, documented)

- **Redis write access is game over for the session layer.** Accepted: Redis
  is a trusted, network-isolated component; mitigating it would mean signing
  every record, which reintroduces the JWT key-management burden ADR 0001
  avoids. Detection (audit anomalies) over prevention here.
- **Revocation propagation window of up to CacheTTL (2s).** Accepted and
  documented as the consistency contract; set `CacheTTL` lower (or to ~1ms,
  disabling the cache in effect) where the trade is wrong.
- **No per-request UA/IP binding enforcement.** The fingerprint and IP are
  stored and returned to callers; sessiond does not itself reject a token
  presented with a different fingerprint (mobile networks and corporate
  proxies make hard binding a support burden). Callers with stricter needs
  can compare and force rotate/revoke.
- **Demo credential check is a fixed map.** Deliberate: sessiond manages
  sessions; authentication is idp's job. The demo exists to exercise the
  session flows, and its comparison is still constant-time with a decoy to
  avoid trivially confirming usernames.
- **Single Redis, no cluster support.** Lua scripts derive keys at runtime,
  which breaks cluster slot hashing. Known ceiling; hash-tagging is the
  upgrade path (ADR 0002).
