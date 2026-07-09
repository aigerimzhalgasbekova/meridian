# ADR 0002: Lua scripts for every check-and-act sequence

**Status:** Accepted · 2026-07-09

## Context

sessiond runs as many stateless nodes against one Redis. Three operations are
inherently multi-step: create (count live sessions, maybe evict, write, index),
touch (check absolute deadline, update last-seen, renew TTL), and rotate (read
old record, delete it, write successor). Interleaved across nodes, each has a
classic race: two creates both observing "4 of 5 sessions" and both writing a
6th; a touch renewing the TTL of a session another node just revoked; a rotate
leaving a window where old and new IDs are both valid (fixation) or neither is
(dropped session).

Candidate mechanisms: optimistic locking (`WATCH`/`MULTI`), a distributed lock
(Redlock), or server-side Lua (`EVAL`).

## Decision

Each of create-under-cap, touch-with-deadline-check, rotate, revoke, and
revoke-all is a single Lua script. The scripts are the *only* writers of
session state.

## Rationale

- Redis executes a script atomically: no other command interleaves. The race
  windows do not narrow — they cease to exist, with no retry loops
  (`WATCH` requires them, and they degenerate under contention on hot users)
  and no lock liveness questions (Redlock's well-known failure modes buy
  nothing here, since the data and the lock would live in the same Redis).
- The scripts stay trivially small (10–30 lines) and each implements one
  invariant, stated in its comment: "the cap counts live sessions only",
  "no sequence of touches extends a session past its deadline", "rotation
  never extends a lifetime".
- The clock is always passed in as an argument rather than read via Redis
  `TIME`: expiry decisions pin to one clock per call, and tests can drive a
  fake clock in lockstep with miniredis `FastForward`.

## Consequences

- Lua is a second language in the codebase; mitigated by keeping scripts
  short, single-purpose, and comment-dense, and by the concurrency hammer
  test that runs them in parallel from two store instances under `-race`.
- Scripts derive keys (`'sess:' .. id`) at runtime, which is invalid under
  Redis Cluster key hashing. Single-node Redis is the deployment target;
  hash-tagging the keys is the known upgrade path if that changes.
- miniredis executes Lua via gopher-lua, so the exact production code paths
  are testable without Docker or a real Redis.
