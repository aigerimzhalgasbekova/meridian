import { describe, expect, it } from 'vitest';
import { memoryQueue } from '../src/queue/memory.js';
import { backoffMs, STALE_CLAIM_MS } from '../src/queue/types.js';
import { Worker } from '../src/queue/worker.js';
import { runQueueContract } from './contract/queue.js';

describe('backoffMs', () => {
  it('grows 1s, 4s, 16s ... capped at 5 minutes', () => {
    expect(backoffMs(1)).toBe(1000);
    expect(backoffMs(2)).toBe(4000);
    expect(backoffMs(3)).toBe(16000);
    expect(backoffMs(10)).toBe(5 * 60 * 1000);
  });
});

// The memory queue claims to mirror FOR UPDATE SKIP LOCKED exactly; the shared
// contract is what holds it to that. postgres runs the same suite in pg.test.ts.
describe('memory queue', () => {
  runQueueContract(() => memoryQueue());
});

describe('memory queue claim semantics', () => {
  it('two concurrent claimers never receive the same job', async () => {
    const q = memoryQueue();
    const now = new Date();
    await q.enqueue('a', {}, { runAt: now });
    await q.enqueue('a', {}, { runAt: now });
    const [j1, j2, j3] = await Promise.all([q.claim(now), q.claim(now), q.claim(now)]);
    const ids = [j1, j2, j3].filter((j) => j !== null).map((j) => j!.id);
    expect(ids).toHaveLength(2);
    expect(new Set(ids).size).toBe(2);
  });
});

describe('worker retry / dead-letter', () => {
  it('retries with exponential backoff then dead-letters at max attempts', async () => {
    const q = memoryQueue();
    let clock = new Date('2026-01-01T00:00:00Z');
    const attempts: number[] = [];
    const worker = new Worker(
      q,
      {
        flaky: async (job) => {
          attempts.push(job.attempts);
          throw new Error('always fails');
        },
      },
      { now: () => clock },
    );
    const job = await q.enqueue('flaky', {}, { maxAttempts: 3, runAt: clock });

    for (let i = 0; i < 5; i++) {
      await worker.tick();
      clock = new Date(clock.getTime() + 10 * 60 * 1000); // jump past any backoff
    }

    expect(attempts).toEqual([1, 2, 3]);
    const dead = await q.get(job.id);
    expect(dead?.status).toBe('dead');
    expect(dead?.lastError).toBe('always fails');
    expect(await q.listByStatus('dead')).toHaveLength(1);
  });

  it('succeeding on a retry completes the job', async () => {
    const q = memoryQueue();
    let clock = new Date('2026-01-01T00:00:00Z');
    let calls = 0;
    const worker = new Worker(
      q,
      {
        flaky: async () => {
          if (++calls < 2) throw new Error('first attempt fails');
        },
      },
      { now: () => clock },
    );
    const job = await q.enqueue('flaky', {}, { runAt: clock });
    await worker.tick();
    clock = new Date(clock.getTime() + backoffMs(1));
    await worker.tick();
    expect(calls).toBe(2);
    expect((await q.get(job.id))?.status).toBe('done');
  });

  it('dead-letters jobs with no registered handler', async () => {
    const q = memoryQueue();
    let clock = new Date('2026-01-01T00:00:00Z');
    const worker = new Worker(q, {}, { now: () => clock });
    const job = await q.enqueue('unknown', {}, { maxAttempts: 1, runAt: clock });
    await worker.tick();
    expect((await q.get(job.id))?.status).toBe('dead');
  });

  it('stop() awaits the in-flight tick so a mid-job shutdown does not strand work', async () => {
    const q = memoryQueue();
    let release!: () => void;
    const gate = new Promise<void>((r) => (release = r));
    let done = false;
    const worker = new Worker(q, {
      slow: async () => {
        await gate;
        done = true;
      },
    });
    await q.enqueue('slow', {});
    worker.start();
    // wait until the handler has actually claimed and entered the slow job
    for (let i = 0; i < 100 && (await q.listByStatus('running')).length === 0; i++) {
      await new Promise((r) => setTimeout(r, 5));
    }
    const stopped = worker.stop();
    release();
    await stopped;
    expect(done).toBe(true);
    expect(await q.listByStatus('done')).toHaveLength(1);
  });

  it('two workers drain a batch without processing any job twice', async () => {
    const q = memoryQueue();
    const now = () => new Date();
    const seen: string[] = [];
    const handler = {
      work: async (job: { id: string }): Promise<void> => {
        seen.push(job.id);
      },
    };
    const w1 = new Worker(q, handler, { now });
    const w2 = new Worker(q, handler, { now });
    for (let i = 0; i < 20; i++) await q.enqueue('work', { i });
    await Promise.all([w1.tick(), w2.tick()]);
    expect(seen).toHaveLength(20);
    expect(new Set(seen).size).toBe(20);
    expect(await q.listByStatus('done')).toHaveLength(20);
  });
  it('a failed complete() is not treated as a handler failure, and the job self-heals', async () => {
    // complete() rejecting (pg pool timeout, RDS failover) inside the handler's
    // try was caught and routed into fail(), which reschedules a job whose
    // side effect already happened — a second email. And with nothing
    // reclaiming a stranded 'running' row while the process stays up, the
    // alternative was losing the job until a restart.
    const q = memoryQueue();
    const clock = new Date('2026-01-01T00:00:00Z');
    const errors: unknown[] = [];
    let runs = 0;
    const failing = { ...q, complete: async () => { throw new Error('pg pool timeout'); } };
    const worker = new Worker(
      failing as typeof q,
      { work: async () => { runs++; } },
      { now: () => clock, onError: (_j, e) => void errors.push(e) },
    );
    const job = await q.enqueue('work', {}, { runAt: clock });

    await expect(worker.tick()).rejects.toThrow('pg pool timeout');
    expect(errors).toHaveLength(0); // bookkeeping failure, not a handler failure
    expect((await q.get(job.id))?.status).toBe('running');
    expect(await q.claim(clock)).toBeNull(); // still held, not double-run immediately

    const later = new Date(clock.getTime() + STALE_CLAIM_MS + 1000);
    expect((await q.claim(later))?.id).toBe(job.id); // reaped without a restart
    expect(runs).toBe(1);
  });

  it('survives a database that is not up yet instead of crash-looping', async () => {
    // A tick rejecting mid-run used to be an unhandled rejection, which under
    // Node's default --unhandled-rejections=throw kills the process. index.ts
    // calls start() unconditionally, so that turns a transient blip into a
    // crash-loop.
    const q = memoryQueue();
    let up = false;
    const failing = {
      ...q,
      claim: async (now: Date) => {
        if (!up) throw new Error('ECONNREFUSED');
        return q.claim(now);
      },
    };
    const seen: string[] = [];
    const errors: unknown[] = [];
    const worker = new Worker(
      failing as typeof q,
      { work: async (job: { id: string }) => void seen.push(job.id) },
      { now: () => new Date(), pollIntervalMs: 5, onPollError: (e) => void errors.push(e) },
    );

    await q.enqueue('work', {});
    worker.start();
    await new Promise((r) => setTimeout(r, 40));
    expect(errors.length).toBeGreaterThan(0);
    expect(seen).toHaveLength(0);

    // Database comes back: the worker is still polling and drains the backlog.
    up = true;
    for (let i = 0; i < 100 && seen.length === 0; i++) await new Promise((r) => setTimeout(r, 5));
    await worker.stop();
    expect(seen).toHaveLength(1);
  });
});
