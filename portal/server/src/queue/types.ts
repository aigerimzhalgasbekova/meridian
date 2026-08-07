// Postgres-backed job queue (SELECT ... FOR UPDATE SKIP LOCKED) with an
// in-memory implementation that mirrors the claim semantics exactly:
// a claimed job is invisible to every other worker until completed or failed.

export type JobStatus = 'pending' | 'running' | 'done' | 'dead';

export interface Job {
  id: string;
  type: string;
  payload: Record<string, unknown>;
  status: JobStatus;
  attempts: number;
  maxAttempts: number;
  /** Not eligible for claiming before this time (backoff scheduling). */
  runAt: Date;
  /** When the current claim was taken; a claim older than STALE_CLAIM_MS is reapable. */
  claimedAt: Date | null;
  lastError: string | null;
  createdAt: Date;
}

/**
 * How long a `running` job may go unfinished before another claim may take it.
 * This is the crash/blip recovery mechanism: a worker that dies mid-job, or
 * whose complete()/fail() call fails on a transient database error, leaves the
 * row `running` forever otherwise — a startup-only requeue never sees it, and
 * an unqualified one would also yank live jobs out of a peer's hands during
 * the two-worker overlap of every rolling deploy.
 * ponytail: a fixed window, not a heartbeat — a job that legitimately runs
 * longer than this gets a concurrent second run, so raise it (or add a
 * claimed_at touch from the handler) before any long-running job type lands.
 * Redelivery is bounded: each reap spends an attempt, and a job that runs out
 * of them is dead-lettered rather than re-handed out every window forever.
 */
export const STALE_CLAIM_MS = 5 * 60 * 1000;

/** lastError written when a job dies from stale reaping rather than a handler throw. */
export const STALE_CLAIM_ERROR = 'claim went stale with no attempts left';

export interface JobQueue {
  enqueue(type: string, payload: Record<string, unknown>, opts?: { maxAttempts?: number; runAt?: Date }): Promise<Job>;
  /**
   * Atomically claim the oldest eligible job — pending and due, or running on a
   * claim that went stale (see STALE_CLAIM_MS) with attempts left — and mark it
   * running as of `now`. Concurrent claimers never receive the same job: FOR
   * UPDATE SKIP LOCKED in Postgres, synchronous mutation in memory. Also
   * dead-letters stale claims that have no attempts left.
   */
  claim(now: Date): Promise<Job | null>;
  /**
   * Marks a job done. `claimedAt` is the stamp on the Job that claim() returned:
   * the write lands only while that exact claim is still the live one, so a
   * straggler answering after the reaper re-handed the job out is ignored.
   */
  complete(id: string, claimedAt: Date): Promise<void>;
  /**
   * Record a failure. Reschedules with exponential backoff until maxAttempts,
   * then parks the job as dead (dead-letter state). Scoped to `claimedAt` like
   * complete(), so a straggler neither resurrects a finished job nor requeues
   * one a peer is still running.
   */
  fail(id: string, error: string, now: Date, claimedAt: Date): Promise<void>;
  get(id: string): Promise<Job | null>;
  listByStatus(status: JobStatus): Promise<Job[]>;
}

/** Exponential backoff: 1s, 4s, 16s, ... capped at 5 minutes. */
export function backoffMs(attempts: number): number {
  return Math.min(1000 * 4 ** (attempts - 1), 5 * 60 * 1000);
}

export const DEFAULT_MAX_ATTEMPTS = 5;
