// Shared conformance suite for JobQueue implementations. The memory queue
// claims "mirrors the claim semantics exactly" (queue/types.ts) — this is what
// holds it to that claim, and it is the only coverage postgresQueue.recover()
// has ever had.
//
// Callers supply a factory returning a *clean* queue per test.
//
// Backend-specific behaviour lives with its backend: true concurrent claiming
// over separate connections (SKIP LOCKED) is only meaningful against postgres,
// and the Worker tests only need one backend.
import { randomUUID } from 'node:crypto';
import { expect, it } from 'vitest';
import { backoffMs, DEFAULT_MAX_ATTEMPTS, type JobQueue } from '../../src/queue/types.js';

export function runQueueContract(makeQueue: () => JobQueue): void {
  it('enqueue: defaults are pending, zero attempts, no error', async () => {
    const q = makeQueue();
    const now = new Date();
    const job = await q.enqueue('send_email', { to: 'a@example.test', nested: { n: [1, 2] } }, { runAt: now });

    expect(job).toMatchObject({
      type: 'send_email',
      status: 'pending',
      attempts: 0,
      maxAttempts: DEFAULT_MAX_ATTEMPTS,
      lastError: null,
    });
    expect(job.payload).toEqual({ to: 'a@example.test', nested: { n: [1, 2] } });
    expect(job.runAt.getTime()).toBe(now.getTime());

    expect(await q.get(job.id)).toMatchObject({ id: job.id, type: 'send_email' });
    expect(await q.get(randomUUID())).toBeNull();
  });

  it('claim: marks running, increments attempts, and hides the job', async () => {
    const q = makeQueue();
    const now = new Date();
    const job = await q.enqueue('t', {}, { runAt: now });

    const claimed = await q.claim(now);
    expect(claimed).toMatchObject({ id: job.id, status: 'running', attempts: 1 });
    // A running job is invisible to every other claimer.
    expect(await q.claim(now)).toBeNull();
    expect((await q.get(job.id))?.status).toBe('running');
  });

  it('claim: returns null on an empty queue and respects runAt scheduling', async () => {
    const q = makeQueue();
    const now = new Date();
    expect(await q.claim(now)).toBeNull();

    const later = await q.enqueue('t', {}, { runAt: new Date(now.getTime() + 60_000) });
    expect(await q.claim(now)).toBeNull(); // not yet eligible
    expect((await q.claim(new Date(now.getTime() + 60_000)))?.id).toBe(later.id);
  });

  it('claim: takes the oldest eligible job first', async () => {
    const q = makeQueue();
    const now = new Date();
    const mid = await q.enqueue('t', { o: 2 }, { runAt: new Date(now.getTime() - 2000) });
    const oldest = await q.enqueue('t', { o: 1 }, { runAt: new Date(now.getTime() - 3000) });
    const newest = await q.enqueue('t', { o: 3 }, { runAt: new Date(now.getTime() - 1000) });

    expect((await q.claim(now))?.id).toBe(oldest.id);
    expect((await q.claim(now))?.id).toBe(mid.id);
    expect((await q.claim(now))?.id).toBe(newest.id);
    expect(await q.claim(now)).toBeNull();
  });

  it('complete: parks the job as done and out of reach', async () => {
    const q = makeQueue();
    const now = new Date();
    const job = await q.enqueue('t', {}, { runAt: now });
    await q.claim(now);
    await q.complete(job.id);

    expect((await q.get(job.id))?.status).toBe('done');
    expect(await q.claim(now)).toBeNull();
    expect((await q.listByStatus('done')).map((j) => j.id)).toEqual([job.id]);
    await expect(q.complete(randomUUID())).resolves.toBeUndefined();
  });

  it('fail: reschedules with exponential backoff, preserving attempts', async () => {
    const q = makeQueue();
    const now = new Date();
    const job = await q.enqueue('t', {}, { maxAttempts: 3, runAt: now });

    await q.claim(now); // attempts -> 1
    await q.fail(job.id, 'boom', now);

    const failed = await q.get(job.id);
    expect(failed).toMatchObject({ status: 'pending', attempts: 1, lastError: 'boom' });
    expect(failed?.runAt.getTime()).toBe(now.getTime() + backoffMs(1));

    // Backed off into the future: not claimable until the delay elapses.
    expect(await q.claim(now)).toBeNull();
    const retried = await q.claim(new Date(now.getTime() + backoffMs(1)));
    expect(retried?.attempts).toBe(2);

    await q.fail(job.id, 'again', now);
    expect((await q.get(job.id))?.runAt.getTime()).toBe(now.getTime() + backoffMs(2));

    await expect(q.fail(randomUUID(), 'x', now)).resolves.toBeUndefined();
  });

  it('fail: dead-letters once attempts reach maxAttempts', async () => {
    const q = makeQueue();
    const now = new Date();
    const job = await q.enqueue('t', {}, { maxAttempts: 1, runAt: now });

    await q.claim(now); // attempts -> 1, which is maxAttempts
    await q.fail(job.id, 'fatal', now);

    expect(await q.get(job.id)).toMatchObject({ status: 'dead', attempts: 1, lastError: 'fatal' });
    // A dead job is never claimed again, however far the clock advances.
    expect(await q.claim(new Date(now.getTime() + 86_400_000))).toBeNull();
    expect((await q.listByStatus('dead')).map((j) => j.id)).toEqual([job.id]);
  });

  it('recover: requeues jobs stranded in running by a crashed worker', async () => {
    const q = makeQueue();
    const now = new Date();
    const stranded = await q.enqueue('t', {}, { runAt: now });
    const done = await q.enqueue('t', {}, { runAt: now });

    await q.claim(now);
    await q.claim(now);
    await q.complete(done.id);
    expect(await q.recover()).toBe(1); // only the still-running one

    expect((await q.get(stranded.id))?.status).toBe('pending');
    expect((await q.get(done.id))?.status).toBe('done'); // untouched
    expect((await q.claim(now))?.id).toBe(stranded.id); // reclaimable

    expect(await q.recover()).toBe(1); // the fresh claim, again reclaimable
  });

  it('listByStatus: partitions the queue', async () => {
    const q = makeQueue();
    const now = new Date();
    const a = await q.enqueue('t', {}, { runAt: now });
    const b = await q.enqueue('t', {}, { runAt: now });
    await q.enqueue('t', {}, { runAt: new Date(now.getTime() + 60_000) });

    await q.claim(now);
    await q.complete(a.id);
    await q.claim(now); // b is running

    expect((await q.listByStatus('done')).map((j) => j.id)).toEqual([a.id]);
    expect((await q.listByStatus('running')).map((j) => j.id)).toEqual([b.id]);
    expect(await q.listByStatus('pending')).toHaveLength(1);
    expect(await q.listByStatus('dead')).toEqual([]);
  });
}
