import { randomUUID } from 'node:crypto';
import { backoffMs, DEFAULT_MAX_ATTEMPTS, type Job, type JobQueue, type JobStatus } from './types.js';

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
        lastError: null,
        createdAt: new Date(),
      };
      jobs.set(job.id, job);
      return { ...job };
    },

    // Mirrors FOR UPDATE SKIP LOCKED: selection + status flip happen in one
    // synchronous step, so a job claimed by one worker is never visible to another.
    async claim(now) {
      let oldest: Job | null = null;
      for (const j of jobs.values()) {
        if (j.status !== 'pending' || j.runAt > now) continue;
        if (!oldest || j.runAt < oldest.runAt || (j.runAt.getTime() === oldest.runAt.getTime() && j.createdAt < oldest.createdAt)) {
          oldest = j;
        }
      }
      if (!oldest) return null;
      oldest.status = 'running';
      oldest.attempts += 1;
      return { ...oldest };
    },

    async complete(id) {
      const j = jobs.get(id);
      if (j) j.status = 'done';
    },

    async fail(id, error, now) {
      const j = jobs.get(id);
      if (!j) return;
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

    async recover() {
      let n = 0;
      for (const j of jobs.values()) if (j.status === 'running') { j.status = 'pending'; n++; }
      return n;
    },
  };
}
