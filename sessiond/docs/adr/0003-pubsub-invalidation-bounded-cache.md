# ADR 0003: Pub/sub invalidation over a strictly bounded local cache

**Status:** Accepted · 2026-07-09

## Context

Validate is the hot path — every authenticated request in the platform hits
it. A Redis round trip per request is affordable but wasteful, since the same
session validates thousands of times between changes. Any per-node cache,
though, reintroduces the exact problem sessions exist to solve: a revoked
session must die *everywhere*, not just on the node that processed the logout.

Redis pub/sub is the obvious invalidation transport, but it is fire-and-forget:
a subscriber that is slow, disconnected, or mid-restart silently misses
messages. A design that needs pub/sub delivery for correctness is broken on
the day it ships.

## Decision

Each node caches validation results (hits *and* misses) for at most
`CacheTTL`, default 2 seconds. All revocations — explicit revoke, revoke-all,
cap eviction, rotation — publish the dead session ID on one channel; nodes
drop matching entries on receipt. If a node's subscription is lost, it flushes
its whole cache before reconnecting.

## Rationale

The correctness argument does not mention pub/sub:

1. Redis is the single point of truth, and the Lua scripts (ADR 0002) are its
   only writers. The cache never writes back.
2. Every cache entry self-expires after `CacheTTL`.
3. Therefore a node that misses *every* broadcast still serves a revoked
   session for at most `CacheTTL` — after which it consults Redis and gets
   the truth.

Pub/sub only tightens the common case from "≤ 2s" to "milliseconds". Because
it is an optimization, its failure modes (missed messages, reconnect gaps)
degrade latency of revocation propagation, never correctness — which is what
makes fire-and-forget acceptable. The revoking node additionally drops its own
cache entry synchronously, so it never depends on its own broadcast.

`CacheTTL` is the single tuning knob and it is an explicit security parameter:
it is precisely the maximum time a revoked session can outlive its revocation
on one node. The default (2s) is chosen so the window is operationally
negligible while still absorbing validation bursts.

Negative caching (remembering "this token is dead") shares the bound in the
other direction: a just-created session might be invisible to a node that
recently cached a miss for its ID — impossible in practice, since IDs are
hashes of fresh 256-bit tokens that cannot have been validated before creation.

## Alternatives rejected

- **No cache**: correct, simple, and the fallback if `CacheTTL=1ms`-style
  configs are used in tests; rejected as the default only because the cache is
  ~90 lines and the bound is provable.
- **Redis 6 client-side caching (`CLIENT TRACKING`)**: server-pushed
  invalidation with the same missed-message caveats, more protocol machinery,
  and no miniredis support — the same bound would still be needed.
- **Consistent hashing so one node owns each session**: kills the stateless-
  node property and turns node failure into session unavailability.

## Consequences

- Tests pin the contract from both sides: propagation is fast when the
  listener runs (two stores, one miniredis), and staleness is bounded by
  `CacheTTL` on a node that never subscribes at all.
- `LastSeenAt` renewal is also amortized: a cached validate does not touch
  Redis, so the idle window renews at `CacheTTL` granularity. Irrelevant at
  2s against a 30m idle timeout.
- Entry lifetime is measured from when the Redis read was *issued*, so once the
  Redis round trip reaches `CacheTTL` every entry is born expired and the cache
  stops absorbing load — exactly when Redis is slowest. Accepted: honouring the
  staleness bound wins over shedding load. The operator signal is the existing
  request log, no new metric: `duration_ms` on `/v1/sessions/validate` at or
  above `CacheTTL` means the cache is effectively off. The lever is raising
  `SESSIOND_CACHE_TTL`, which widens the staleness bound explicitly.
