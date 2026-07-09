# ADR 0001: Sliding-window counter for rate limiting

**Status:** Accepted · 2026-07-09

## Context

Sentinel rate-limits authentication traffic per IP, per user, and per OAuth
client. Candidate algorithms: fixed window, sliding log, token bucket, leaky
bucket, sliding-window counter. Requirements: O(1) memory per key (millions
of keys), no boundary-burst artifact, honest `Retry-After`, and state that
maps onto Redis primitives so multiple sentinel instances can share limits.

## Decision

Sliding-window counter: two fixed-window counters per key (current +
previous); effective count = `cur + prev × overlap_fraction`. Burst control
is the same mechanism over a shorter window (default `Window/10`), so one
algorithm serves both sustained and burst policies.

## Rationale

- **Fixed window** admits 2× the limit around a boundary (N requests at
  59.9s, N more at 60.1s). Unacceptable for a brute-force gate.
- **Sliding log** is exact but O(requests) memory per key — an attacker
  inflates your memory by hammering you, which inverts the defense.
- **Token bucket** is O(1) and fine, but its state (fractional tokens + last
  refill time) needs a read-modify-write that must be wrapped in a Lua script
  for atomicity, and burst vs. sustained requires two buckets anyway.
- **Sliding-window counter** is O(1), bounds boundary error to a few percent
  (Cloudflare measured ~0.003% of requests wrongly admitted at 6% error
  worst-case), and its state is two integers: Redis `INCR` + `EXPIRE`, the
  cheapest atomic primitives there are. The weighted estimate assumes uniform
  arrival in the previous window — a smoothing approximation we accept.

`Retry-After` is computed by inverting the weighted formula: the earliest
time the previous-window contribution decays enough to admit one request.
Denied requests still increment counters — a client hammering past its limit
keeps itself limited.

## Consequences

- Accuracy is approximate near window edges (bounded, slightly conservative
  in the safe direction for auth traffic).
- The in-memory `Store` and a future Redis store share the exact `Hit`
  contract; tests exercise the algorithm without Redis.
