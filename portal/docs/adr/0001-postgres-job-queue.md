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
- Handlers must be idempotent: attempts increment at claim time, and a worker
  crash after a side effect re-runs the job. The mail transport writes
  `outbox/<job-id>.json`, so a retry overwrites rather than duplicates.
