import { describe, expect, it } from 'vitest';
import { memoryQueue } from '../src/queue/memory.js';
import { backoffMs } from '../src/queue/types.js';
import { Worker } from '../src/queue/worker.js';

describe('backoffMs', () => {
  it('grows 1s, 4s, 16s ... capped at 5 minutes', () => {
    expect(backoffMs(1)).toBe(1000);
    expect(backoffMs(2)).toBe(4000);
    expect(backoffMs(3)).toBe(16000);
    expect(backoffMs(10)).toBe(5 * 60 * 1000);
  });
});

describe('memory queue claim semantics (mirrors FOR UPDATE SKIP LOCKED)', () => {
  it('two concurrent claimers never receive the same job', async () => {
    const q = memoryQueue();
    await q.enqueue('a', {});
    await q.enqueue('a', {});
    const now = new Date();
    const [j1, j2, j3] = await Promise.all([q.claim(now), q.claim(now), q.claim(now)]);
    const ids = [j1, j2, j3].filter((j) => j !== null).map((j) => j!.id);
    expect(ids).toHaveLength(2);
    expect(new Set(ids).size).toBe(2);
  });

  it('a running job is invisible until failed back to pending', async () => {
    const q = memoryQueue();
    const job = await q.enqueue('a', {});
    const now = new Date();
    expect((await q.claim(now))?.id).toBe(job.id);
    expect(await q.claim(now)).toBeNull();
    await q.fail(job.id, 'boom', now);
    // Rescheduled into the future by backoff: still not claimable "now".
    expect(await q.claim(now)).toBeNull();
    expect((await q.claim(new Date(now.getTime() + backoffMs(1))))?.id).toBe(job.id);
  });

  it('respects runAt scheduling and claims oldest first', async () => {
    const q = memoryQueue();
    const now = new Date();
    const later = await q.enqueue('a', {}, { runAt: new Date(now.getTime() + 60_000) });
    const early = await q.enqueue('a', {}, { runAt: new Date(now.getTime() - 60_000) });
    expect((await q.claim(now))?.id).toBe(early.id);
    expect(await q.claim(now)).toBeNull();
    expect((await q.claim(new Date(now.getTime() + 60_000)))?.id).toBe(later.id);
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

  it('recover() requeues jobs stranded in running back to pending', async () => {
    const q = memoryQueue();
    const job = await q.enqueue('a', {});
    const now = new Date();
    expect((await q.claim(now))?.id).toBe(job.id); // now 'running'
    expect(await q.claim(now)).toBeNull(); // invisible while running
    expect(await q.recover()).toBe(1);
    expect((await q.claim(now))?.id).toBe(job.id); // reclaimable again
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
});
