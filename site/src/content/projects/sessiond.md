---
name: sessiond
title: sessiond
pitch: Server-side sessions as a service — opaque tokens in Redis, cross-node revocation with a provable staleness bound.
challenge: Distributed state — making revocation propagate to every node while keeping the hot validate path cheap, with a cache-consistency argument you can state in one sentence.
tech: [Go, Redis, Lua, miniredis]
order: 3
---

## What it is

Distributed browser sessions: opaque tokens whose SHA-256 hashes live in Redis, sliding idle expiry under a hard absolute cap, per-user concurrent-session limits, and global revocation. Within Meridian, idp and portal are the intended callers; sessiond trusts only bearer-authenticated services, never browsers (except its built-in `/demo`, which exists to make the behavior visible).

## The architectural challenge

Any per-node cache reintroduces exactly the problem sessions exist to solve: a revoked session must die *everywhere*. And Redis pub/sub — the obvious invalidation transport — is fire-and-forget; a design that needs delivery for correctness is broken the day it ships. sessiond's answer ([ADR 0003](https://github.com/aigerimzhalgasbekova/meridian/blob/main/sessiond/docs/adr/0003-pubsub-invalidation-bounded-cache.md)) is a consistency argument that never mentions pub/sub:

1. Redis is the single point of truth; the Lua scripts are its only writers. The cache never writes back.
2. Every cache entry self-expires after `CacheTTL` (default 2s).
3. Therefore a node that misses *every* broadcast still serves a revoked session for at most `CacheTTL`.

Pub/sub only tightens "≤ 2s" to "milliseconds". Because it's an optimization, its failure modes degrade latency, never correctness. `CacheTTL` is an explicit security parameter: precisely the maximum time a revoked session can outlive its revocation on one node.

## Key design decisions

- **[ADR 0001 — opaque tokens, not JWTs.](https://github.com/aigerimzhalgasbekova/meridian/blob/main/sessiond/docs/adr/0001-opaque-tokens-not-jwt.md)** Every hard requirement of sessions — logout-now, concurrent-session limits, sliding expiry — is a statement about server-side state. Once that state exists, a JWT's one advantage evaporates and its costs remain. Redis stores only SHA-256 hashes, so a snapshot or read-only compromise yields nothing presentable.
- **[ADR 0002 — one Lua script per check-and-act sequence.](https://github.com/aigerimzhalgasbekova/meridian/blob/main/sessiond/docs/adr/0002-lua-scripts-for-atomicity.md)** Create-under-cap, touch-with-deadline-check, rotate, revoke: each is a single atomic script, so races between nodes don't narrow — they cease to exist. The clock is always passed in as an argument, so tests drive a fake clock in lockstep with miniredis.

```lua
-- touchScript: validate + renew atomically; the deadline re-check protects
-- against clock-skewed nodes and restored snapshots with stale TTLs.
if redis.call('EXISTS', KEYS[1]) == 0 then return {} end
local now = tonumber(ARGV[1])
local deadline = tonumber(redis.call('HGET', KEYS[1], 'deadline_ms'))
if now >= deadline then
  redis.call('DEL', KEYS[1])
  return {}
end
```

- **Two clocks enforce expiry:** the Redis key TTL implements the sliding idle window cheaply, and the absolute deadline stored *inside* the record is re-checked by the touch script — a stale TTL can never resurrect a session past its cap.

## Security highlights

From the [threat model](https://github.com/aigerimzhalgasbekova/meridian/blob/main/sessiond/THREAT_MODEL.md): missing, expired, and revoked sessions are one indistinguishable `404` — the API is deliberately not a validity oracle; rotation kills the old ID and writes the new one in the same script, so there's no fixation window; API tokens are hashed then compared in constant time, and zero configured tokens fails closed (503), never open; realm and user IDs pass an allowlist before being spliced into Redis keys; only truncated UA fingerprints are stored, not raw strings.

## Verified by

- `go test -race ./...` — **23 tests pass** (run 2026-07-10; miniredis-backed, no Docker).
- The suite pins contracts, not happy paths: sliding vs absolute expiry under a fake clock moved in lockstep with miniredis `FastForward`; deadline enforcement when the Redis TTL is stale; cap eviction and rejection; revocation/rotation propagation across two store instances; the bounded-staleness window measured on a node that never subscribes; and a parallel create/touch/rotate/revoke hammer asserting the per-user cap holds on every node's view.

## Code worth reading

- [`internal/store/scripts.go`](https://github.com/aigerimzhalgasbekova/meridian/blob/main/sessiond/internal/store/scripts.go) — all five Lua scripts, each 10–30 lines with its invariant stated in the comment.
- [`internal/store/`](https://github.com/aigerimzhalgasbekova/meridian/tree/main/sessiond/internal/store) — the bounded cache and pub/sub listener.
