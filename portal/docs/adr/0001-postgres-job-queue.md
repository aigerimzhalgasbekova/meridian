# ADR 0001: Postgres as the job queue, not Redis or SQS

**Status:** Accepted · 2026-07-09

## Context

Portal sends email asynchronously (verification, password reset). That needs a
durable queue with retries and a dead-letter state. The conventional choices
are Redis (BullMQ), SQS, or a database table.

## Decision

A `jobs` table in the same Postgres database, claimed with
`SELECT … FOR UPDATE SKIP LOCKED`, polled by an in-process worker.
Exponential backoff (1s·4ⁿ, capped at 5 min), `max_attempts`, then a `dead`
status as the dead-letter parking lot.

## Rationale

- **One fewer system.** Portal already has Postgres for users, sessions, and
  tokens. Redis or SQS adds an infrastructure component, a client library, a
  failure mode, and a local-dev story — to move a handful of emails per minute.
- **Transactional enqueue.** A job inserted in the same database as the state
  change it follows can share a transaction; an external queue reintroduces the
  dual-write problem this project's volume never justifies solving.
- **`FOR UPDATE SKIP LOCKED` is the point.** It is the textbook mechanism for
  competing consumers on a relational queue: concurrent workers each lock a
  different row, with no advisory locks and no polling contention. Demonstrating
  it correctly *is* the showcase.
- **Known ceiling.** Row-claim queues degrade around thousands of jobs/second
  (table and index bloat, vacuum pressure). Portal is orders of magnitude below
  that. If the platform ever centralizes async work, handlers are idempotent
  and the `JobQueue` interface is five methods — a broker swap is contained.

## Consequences

- Polling (500 ms) adds up to that much latency per email; acceptable.
- The in-memory implementation mirrors claim semantics (claim + status flip is
  one atomic step), so retry/backoff/dead-letter and two-worker exclusivity are
  tested without a database; the same suite runs against real Postgres when
  `TEST_DATABASE_URL` is set.
- A claim is owned and expires. `claimed_at` is set at claim time and is the
  ownership token: `complete` and `fail` write a terminal state only `WHERE
  status = 'running' AND claimed_at = <the stamp claim() returned>`. `status`
  alone is not ownership — a reaped job is `running` again, so a straggler's
  late `fail()` would requeue a job a peer is mid-way through and its late
  `complete()` would swallow the peer's real failure. A `running` job becomes
  claimable again once its claim is `STALE_CLAIM_MS` (5 min) old *and it has
  attempts left*; a stale claim with none is dead-lettered, so a handler that
  always outlives the window is not redelivered every 5 minutes forever. That replaced a startup-only `recover()` that requeued *every*
  running row: harmless with one worker, but ECS runs two during every rolling
  deploy (`deployment_maximum_percent = 200`), where it handed a peer's live
  job to a second worker and let the loser's late `fail()` flip an already-done
  job back to `pending`. The stale window also covers the case a startup
  requeue never could — a `complete()`/`fail()` that fails on a transient
  database error while the process stays up — so nothing is stranded until a
  restart. Ceiling: a job that legitimately runs longer than the window gets a
  concurrent second run and burns an attempt each window until it dead-letters;
  raise it or heartbeat `claimed_at` before adding one.
- Handlers must be idempotent: attempts increment at claim time, and a worker
  crash after a side effect re-runs the job. Note that today this is supplied
  entirely by the *dev* transport writing `outbox/<job-id>.json`, where a retry
  overwrites rather than duplicates. An SES/SMTP transport has no such
  property; it must bring its own idempotency (a `sent_messages(job_id)` row,
  or a provider idempotency key) before it ships, or a retried job is a second
  delivered email carrying a live token.
