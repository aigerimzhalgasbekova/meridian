---
title: Sessions at scale
chapter: 4
summary: sessiond — why browser sessions are opaque tokens, Lua-script atomicity, and pub/sub invalidation with a provable staleness bound.
---

Meridian already has a JWT pipeline — keysmith signs, everyone verifies locally. The tempting move for browser sessions is to reuse it: issue a signed token, validate statelessly, skip Redis. [sessiond](/projects/sessiond/) exists to demonstrate why that's wrong, and what the right thing costs.

## Opaque versus JWT

Every hard requirement of a session system is a statement about *server-side state* ([ADR 0001](https://github.com/aikazzh/portfolio/blob/main/sessiond/docs/adr/0001-opaque-tokens-not-jwt.md)):

- **Logout / logout-everywhere** means destroying state now, not waiting for `exp`. A JWT revocation list checked on every request *is* a session store — with a signature bolted on that no longer buys anything.
- **Concurrent-session limits** require counting live sessions per user: an index, therefore state.
- **Sliding idle expiry** requires recording last-seen: a write per touch.

Once that state exists, the JWT's one advantage (stateless validation) evaporates and its costs remain: attacker-readable claims, a signing-key dependency in the critical path, revocation always lagging. So sessions are 256-bit random opaque tokens, and Redis stores only the SHA-256 of each one. A Redis snapshot, a replication-stream tap, or a read-only compromise yields a pile of unpresentable digests — and unsalted SHA-256 is sufficient, because the preimage is 256 bits of CSPRNG output with no structure for rainbow tables to exploit. JWTs remain the right tool for *service-to-service* claims; that's keysmith's domain.

## Every multi-step decision is one Lua script

sessiond runs as many stateless nodes against one Redis. Create (count live sessions, maybe evict, write, index), touch (check deadline, update last-seen, renew TTL), and rotate (read old, delete, write successor) are each classic multi-step races when two nodes interleave. [ADR 0002](https://github.com/aikazzh/portfolio/blob/main/sessiond/docs/adr/0002-lua-scripts-for-atomicity.md)'s answer: each operation is a single server-side Lua script, and the scripts are the *only* writers of session state. Redis executes a script atomically, so the race windows don't narrow — they cease to exist, with no retry loops (`WATCH` degenerates under contention on hot users) and no distributed-lock liveness questions.

The scripts stay 10–30 lines, each stating its invariant. Here's touch, from [`scripts.go`](https://github.com/aikazzh/portfolio/blob/main/sessiond/internal/store/scripts.go):

```lua
if redis.call('EXISTS', KEYS[1]) == 0 then return {} end
local now = tonumber(ARGV[1])
local deadline = tonumber(redis.call('HGET', KEYS[1], 'deadline_ms'))
if now >= deadline then
  redis.call('DEL', KEYS[1])
  return {}
end
redis.call('HSET', KEYS[1], 'seen_ms', ARGV[1])
local ttl = tonumber(ARGV[2])
if deadline - now < ttl then ttl = deadline - now end
redis.call('PEXPIRE', KEYS[1], ttl)
return redis.call('HGETALL', KEYS[1])
```

Two details are load-bearing. First, **two clocks enforce expiry**: the Redis key TTL implements the sliding idle window cheaply, while the absolute deadline stored *inside* the record is re-checked by the script — so a stale TTL (clock skew, a restored snapshot) can never resurrect a session past its cap. Second, **the clock is an argument** (`ARGV[1]`), never Redis `TIME`: expiry decisions pin to one clock per call, and tests drive a fake clock in lockstep with miniredis's `FastForward`. That choice is why the entire suite runs without Docker: miniredis executes these exact Lua scripts via gopher-lua.

Rotation gets the same treatment: the old ID dies and the new one takes over in the same atomic step — no window where both are valid (fixation) or neither is (dropped session) — and `created_ms`/`deadline_ms` carry over, so rotation never extends a lifetime.

## Invalidation with a bound you can state in one sentence

Validate is the hot path — every authenticated request in the platform hits it. A per-node cache is the obvious optimization, and it reintroduces exactly the problem sessions exist to solve: a revoked session must die everywhere. Redis pub/sub is the obvious invalidation transport, and it's fire-and-forget — a subscriber that's slow, disconnected, or mid-restart silently misses messages. A design that needs pub/sub delivery for correctness is broken on the day it ships.

[ADR 0003](https://github.com/aikazzh/portfolio/blob/main/sessiond/docs/adr/0003-pubsub-invalidation-bounded-cache.md)'s resolution is a correctness argument that never mentions pub/sub:

1. Redis is the single point of truth, and the Lua scripts are its only writers. The cache never writes back.
2. Every cache entry self-expires after `CacheTTL` (default 2 seconds).
3. Therefore a node that misses *every* broadcast still serves a revoked session for at most `CacheTTL` — after which it consults Redis and gets the truth.

Pub/sub only tightens the common case from "≤ 2s" to "milliseconds". Because it's an optimization, its failure modes degrade revocation-propagation latency, never correctness — which is exactly what makes fire-and-forget acceptable. The revoking node drops its own cache entry synchronously, so it never depends on its own broadcast; a node that loses its subscription flushes its whole cache before reconnecting.

`CacheTTL` is the single tuning knob, and it's explicitly a security parameter: precisely the maximum time a revoked session can outlive its revocation on one node. The alternatives were rejected for concrete reasons — no cache is correct but leaves 90 lines of provably-bounded win on the table; Redis 6 client-side caching has the same missed-message caveats with more protocol machinery; consistent hashing kills the stateless-node property.

## The API is not an oracle

A detail from the [threat model](https://github.com/aikazzh/portfolio/blob/main/sessiond/THREAT_MODEL.md) worth copying: missing, expired, and revoked sessions all return one indistinguishable `404 not_found`, and revocation is an idempotent `204`. The API deliberately refuses to be a validity oracle for probing which sessions exist. Similarly: zero configured API tokens makes the service fail closed (503) rather than open, and realm/user IDs pass an `[A-Za-z0-9._-]{1,64}` allowlist before being spliced into Redis keys.

**Verified by:** 23 tests under `-race`, all miniredis-backed: sliding-vs-absolute expiry on a fake clock, deadline enforcement against stale TTLs, cap eviction and rejection, propagation across two store instances, the staleness bound measured on a node that never subscribes, and a parallel create/touch/rotate/revoke hammer asserting the per-user cap holds on every node's view.
