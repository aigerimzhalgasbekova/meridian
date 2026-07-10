# sessiond — Distributed Session Service

Server-side sessions as a service: opaque tokens whose hashes live in Redis,
sliding idle expiry under a hard absolute cap, per-user concurrent-session
limits, and global revocation that propagates to every node with a *provable*
staleness bound.

Within Meridian, idp and portal call sessiond to manage browser sessions;
sessiond itself trusts only bearer-authenticated services, never browsers
(except the built-in `/demo`, which exists to make the behavior visible).

## Why this project is interesting

1. **Opaque tokens, not JWTs — deliberately.** Sessions are the one place
   where "stateless" JWTs are the wrong tool: logout, concurrent-session
   limits, and admin revocation all require server-side state anyway, so
   pretending otherwise just adds a signature to look at. sessiond stores only
   the SHA-256 of each 256-bit random token; a Redis snapshot or read-only
   compromise yields nothing presentable. See
   [ADR 0001](docs/adr/0001-opaque-tokens-not-jwt.md).

2. **Every multi-step decision is one Lua script.** Create-under-cap, touch
   with deadline re-check, and rotate all execute atomically inside Redis, so
   two nodes racing the same user's session cap — or a touch racing a
   revocation — serialize on the single point of truth instead of
   interleaving. See [ADR 0002](docs/adr/0002-lua-scripts-for-atomicity.md).

3. **A cache-consistency argument you can state in one sentence.** Each node
   caches validation results for at most `CacheTTL` (default 2s). Revocations
   broadcast over Redis pub/sub drop entries immediately; a *missed* broadcast
   therefore extends a revoked session on one node by at most `CacheTTL`,
   because the cache never writes back to Redis and every entry self-expires.
   Best-effort pub/sub becomes safe because it is an optimization, not a
   correctness dependency. See
   [ADR 0003](docs/adr/0003-pubsub-invalidation-bounded-cache.md).

## Session lifecycle

```
create ──► live ──touch──► live (idle TTL renewed, clamped to deadline)
             │
             ├─ idle > IdleTTL ────────────► expired (Redis TTL)
             ├─ now ≥ absolute deadline ───► expired (script re-check)
             ├─ revoke / revoke-all ───────► revoked (broadcast)
             ├─ evicted by cap ────────────► revoked (broadcast)
             └─ rotate ────────────────────► old ID dead (broadcast), new ID
                                             carries created-at + deadline over
```

Two clocks enforce expiry: the Redis key TTL implements the sliding idle
window cheaply, and the absolute deadline stored *inside* the record is
re-checked by the touch script — so a stale TTL (clock skew, restored
snapshot) can never resurrect a session past its cap.

## Opaque sessions vs JWTs

| | Opaque (sessiond) | JWT |
|---|---|---|
| Instant revocation | Yes — delete the record | No — wait for `exp`, or build a revocation list (which *is* a session store) |
| Concurrent-session limits | Per-user index, atomic cap | Impossible without server state |
| Token theft blast radius | Bounded by idle + absolute TTL and revocability | Full lifetime of the token |
| What the storage leaks | SHA-256 hashes, useless to present | n/a (but claims are attacker-readable) |
| Validation cost | Redis round trip, amortized by a bounded local cache | Local signature check |

The last row is the only JWT win, and the bounded cache buys most of it back.
JWTs stay the right tool for *service-to-service* claims (keysmith's domain);
browser sessions belong here.

## Layout

```
internal/store/    Redis session store: Lua scripts, local cache, pub/sub
internal/server/   HTTP API + browser demo
cmd/sessiond/      the daemon
docs/adr/          decision records
```

## API

All `/v1` endpoints require a service bearer token (`SESSIOND_API_TOKENS`).

| Endpoint | Purpose |
|----------|---------|
| `GET /healthz` | Liveness (no auth) |
| `POST /v1/sessions` | Create; returns the opaque token exactly once |
| `POST /v1/sessions/validate` | Validate + touch (renews idle window) |
| `POST /v1/sessions/rotate` | New session ID, old atomically invalidated (fixation defense) |
| `POST /v1/sessions/revoke` | Revoke one session by token (logout) or ID (admin) |
| `GET /v1/users/{realm}/{user}/sessions` | List live sessions, oldest first |
| `DELETE /v1/users/{realm}/{user}/sessions` | Revoke all (logout everywhere) |

Missing, expired, and revoked sessions are all `404 not_found` — the API is
deliberately not a validity oracle. Revocation is idempotent `204`.

## Run it

```sh
# Dev mode: embedded miniredis, demo mounted at /demo
make run-dev
# then open http://localhost:8082/demo/ (alice/wonderland, bob/builder)

# Production shape
SESSIOND_REDIS_URL=redis://redis:6379/0 \
SESSIOND_API_TOKENS=$SERVICE_TOKEN \
  ./bin/sessiond
```

Configuration is environment-only; see `cmd/sessiond/main.go` for the full
variable list (idle/absolute TTLs, per-user cap, evict-oldest vs reject
policy, cache TTL).

## Tests

```sh
make test       # go test -race ./... — miniredis-backed, no Docker required
make test-int   # + a real Redis; needs TEST_REDIS_URL
```

The default suite pins the contracts, not just the happy paths: sliding vs
absolute expiry under a fake clock moved in lockstep with miniredis
`FastForward`, deadline enforcement when the Redis TTL is stale, cap eviction
and rejection, revocation/rotation propagation across two store instances
sharing one miniredis, the bounded-staleness window on a node that misses every
broadcast, a parallel create/touch/rotate/revoke hammer whose invariant is that
the per-user cap holds on every node's view, and 32 callers racing to create a
session for one user — which fails loudly if the cap is ever enforced by
anything other than a single script.

That last one holds because miniredis is a faithful fake *for atomicity*: it
applies each command under a lock, exactly as single-threaded Redis does. Where
it stops being faithful is everything it reimplements rather than runs, and
that is what `make test-int` covers:

| miniredis | Redis | What only the real thing shows |
|-----------|-------|-------------------------------|
| gopher-lua | Lua 5.1 in Redis | That the scripts mean the same thing to a different interpreter: `tostring()`/`tonumber()` number formatting and the Lua→RESP reply conversion. `rotateScript` round-trips `deadline_ms` through `tostring()`, so its correctness rests on Redis's `%.14g`, not gopher-lua's. |
| `FastForward` | a clock | That the `PEXPIRE` we issue carries the TTL we think it does, and that a touch renews it. |
| in-process channels | pub/sub over a socket | That a revocation is serialized, published, and delivered to another node. |

miniredis is not a strawman here: it implements `EVAL`, `EVALSHA` and `SCRIPT`,
so the scripts genuinely load and run under it. What it cannot tell you is
whether they mean the same thing to the interpreter Redis actually embeds.

```sh
docker run -d --name meridian-redis-test -p 6380:6379 redis:7
TEST_REDIS_URL='redis://localhost:6380/1' make test-int
docker rm -f meridian-redis-test
```

The suite `FLUSHDB`s between tests, so point `TEST_REDIS_URL` at a throwaway
database. `make test-int` sets `REQUIRE_TEST_REDIS_URL=1`, so a missing Redis
fails rather than skipping every test it exists to run; CI does the same
against an ephemeral `redis:7` service.

## Docs

- [THREAT_MODEL.md](THREAT_MODEL.md) — assets, trust boundaries, abuse cases,
  residual risk
- [ADR 0001](docs/adr/0001-opaque-tokens-not-jwt.md) — opaque tokens, not JWTs
- [ADR 0002](docs/adr/0002-lua-scripts-for-atomicity.md) — Lua scripts for atomicity
- [ADR 0003](docs/adr/0003-pubsub-invalidation-bounded-cache.md) — pub/sub invalidation, bounded cache
