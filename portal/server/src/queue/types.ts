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
  lastError: string | null;
  createdAt: Date;
}

export interface JobQueue {
  enqueue(type: string, payload: Record<string, unknown>, opts?: { maxAttempts?: number; runAt?: Date }): Promise<Job>;
  /**
   * Atomically claim the oldest eligible pending job (status=pending, runAt<=now)
   * and mark it running. Concurrent claimers never receive the same job —
   * FOR UPDATE SKIP LOCKED in Postgres, synchronous mutation in memory.
   */
  claim(now: Date): Promise<Job | null>;
  complete(id: string): Promise<void>;
  /**
   * Record a failure. Reschedules with exponential backoff until maxAttempts,
   * then parks the job as dead (dead-letter state).
   */
  fail(id: string, error: string, now: Date): Promise<void>;
  get(id: string): Promise<Job | null>;
  listByStatus(status: JobStatus): Promise<Job[]>;
  /**
   * Requeue jobs left 'running' by a crashed/killed worker back to 'pending'.
   * Called once on worker startup; returns how many were reclaimed.
   */
  recover(): Promise<number>;
}

/** Exponential backoff: 1s, 4s, 16s, ... capped at 5 minutes. */
export function backoffMs(attempts: number): number {
  return Math.min(1000 * 4 ** (attempts - 1), 5 * 60 * 1000);
}

export const DEFAULT_MAX_ATTEMPTS = 5;
