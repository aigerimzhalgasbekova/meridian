import { randomUUID } from 'node:crypto';
import {
  backoffMs,
  DEFAULT_MAX_ATTEMPTS,
  STALE_CLAIM_ERROR,
  STALE_CLAIM_MS,
  type Job,
  type JobQueue,
  type JobStatus,
} from './types.js';

/**
 * Only the holder of *this* claim writes a terminal state. `status === 'running'`
 * alone is not ownership: once the reaper has re-handed the job out it is running
 * again, so a straggler's late fail() would requeue a job a peer is mid-way
 * through (a third delivery) and its late complete() would swallow the peer's
 * real failure. Mirrors `AND claimed_at = $n` in the SQL backend.
 */
function held(j: Job | undefined, claimedAt: Date): j is Job {
  return j?.status === 'running' && j.claimedAt?.getTime() === claimedAt.getTime();
}

export function memoryQueue(): JobQueue {
  const jobs = new Map<string, Job>();

  return {
    async enqueue(type, payload, opts = {}) {
      const job: Job = {
        id: randomUUID(),
        type,
        payload,
        status: 'pending',
        attempts: 0,
        maxAttempts: opts.maxAttempts ?? DEFAULT_MAX_ATTEMPTS,
        runAt: opts.runAt ?? new Date(),
        claimedAt: null,
        lastError: null,
        createdAt: new Date(),
      };
      jobs.set(job.id, job);
      return { ...job };
    },

    // Mirrors FOR UPDATE SKIP LOCKED: selection + status flip happen in one
    // synchronous step, so a job claimed by one worker is never visible to another.
    async claim(now) {
      // `claimedAt ?? runAt` covers rows claimed before claimed_at existed
      // (mirrors the SQL COALESCE): they must still be reclaimable, not stuck.
      const staleBefore = new Date(now.getTime() - STALE_CLAIM_MS);
      const stale = (j: Job): boolean => j.status === 'running' && (j.claimedAt ?? j.runAt) < staleBefore;
      const eligible = (j: Job): boolean =>
        (j.status === 'pending' && j.runAt <= now) || (stale(j) && j.attempts < j.maxAttempts);
      let oldest: Job | null = null;
      for (const j of jobs.values()) {
        // A stale claim spends an attempt, so without this a handler that always
        // outlives the window is redelivered every window forever. Dead-letter it.
        if (stale(j) && j.attempts >= j.maxAttempts) {
          j.status = 'dead';
          j.lastError = STALE_CLAIM_ERROR;
          continue;
        }
        if (!eligible(j)) continue;
        if (!oldest || j.runAt < oldest.runAt || (j.runAt.getTime() === oldest.runAt.getTime() && j.createdAt < oldest.createdAt)) {
          oldest = j;
        }
      }
      if (!oldest) return null;
      oldest.status = 'running';
      oldest.attempts += 1;
      oldest.claimedAt = now;
      return { ...oldest };
    },

    async complete(id, claimedAt) {
      const j = jobs.get(id);
      if (held(j, claimedAt)) j.status = 'done';
    },

    async fail(id, error, now, claimedAt) {
      const j = jobs.get(id);
      if (!held(j, claimedAt)) return;
      j.lastError = error;
      if (j.attempts >= j.maxAttempts) {
        j.status = 'dead';
      } else {
        j.status = 'pending';
        j.runAt = new Date(now.getTime() + backoffMs(j.attempts));
      }
    },

    async get(id) {
      const j = jobs.get(id);
      return j ? { ...j } : null;
    },

    async listByStatus(status: JobStatus) {
      return [...jobs.values()].filter((j) => j.status === status).map((j) => ({ ...j }));
    },
  };
}
