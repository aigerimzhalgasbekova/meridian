// Shared conformance suite for JobQueue implementations. The memory queue
// claims "mirrors the claim semantics exactly" (queue/types.ts) — this is what
// holds it to that claim, and it is the only coverage the postgres queue's
// stale-claim reaper and terminal-write guards have ever had.
//
// Callers supply a factory returning a *clean* queue per test.
//
// Backend-specific behaviour lives with its backend: true concurrent claiming
// over separate connections (SKIP LOCKED) is only meaningful against postgres,
// and the Worker tests only need one backend.
import { randomUUID } from 'node:crypto';
import { expect, it } from 'vitest';
import {
  backoffMs,
  DEFAULT_MAX_ATTEMPTS,
  STALE_CLAIM_ERROR,
  STALE_CLAIM_MS,
  type JobQueue,
} from '../../src/queue/types.js';

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
    const c = await q.claim(now);
    await q.complete(job.id, c!.claimedAt!);

    expect((await q.get(job.id))?.status).toBe('done');
    expect(await q.claim(now)).toBeNull();
    expect((await q.listByStatus('done')).map((j) => j.id)).toEqual([job.id]);
    await expect(q.complete(randomUUID(), now)).resolves.toBeUndefined();
  });

  it('fail: reschedules with exponential backoff, preserving attempts', async () => {
    const q = makeQueue();
    const now = new Date();
    const job = await q.enqueue('t', {}, { maxAttempts: 3, runAt: now });

    const first = await q.claim(now); // attempts -> 1
    await q.fail(job.id, 'boom', now, first!.claimedAt!);

    const failed = await q.get(job.id);
    expect(failed).toMatchObject({ status: 'pending', attempts: 1, lastError: 'boom' });
    expect(failed?.runAt.getTime()).toBe(now.getTime() + backoffMs(1));

    // Backed off into the future: not claimable until the delay elapses.
    expect(await q.claim(now)).toBeNull();
    const retried = await q.claim(new Date(now.getTime() + backoffMs(1)));
    expect(retried?.attempts).toBe(2);

    await q.fail(job.id, 'again', now, retried!.claimedAt!);
    expect((await q.get(job.id))?.runAt.getTime()).toBe(now.getTime() + backoffMs(2));

    await expect(q.fail(randomUUID(), 'x', now, now)).resolves.toBeUndefined();
  });

  it('fail: dead-letters once attempts reach maxAttempts', async () => {
    const q = makeQueue();
    const now = new Date();
    const job = await q.enqueue('t', {}, { maxAttempts: 1, runAt: now });

    const c = await q.claim(now); // attempts -> 1, which is maxAttempts
    await q.fail(job.id, 'fatal', now, c!.claimedAt!);

    expect(await q.get(job.id)).toMatchObject({ status: 'dead', attempts: 1, lastError: 'fatal' });
    // A dead job is never claimed again, however far the clock advances.
    expect(await q.claim(new Date(now.getTime() + 86_400_000))).toBeNull();
    expect((await q.listByStatus('dead')).map((j) => j.id)).toEqual([job.id]);
  });

  it('claim: reclaims a job stranded in running, but only once the claim goes stale', async () => {
    // This is the whole crash-recovery mechanism now that the blanket startup
    // requeue is gone: a worker that dies mid-job (or whose complete() call
    // fails on a database blip) leaves the row 'running' forever otherwise.
    const q = makeQueue();
    const now = new Date();
    const stranded = await q.enqueue('t', {}, { runAt: now });
    const done = await q.enqueue('t', {}, { runAt: now });

    const claims = [await q.claim(now), await q.claim(now)];
    await q.complete(done.id, claims.find((c) => c?.id === done.id)!.claimedAt!);

    // A peer's fresh claim is off limits — that is what makes this safe to run
    // while a second worker exists (every rolling deploy overlaps two).
    expect(await q.claim(new Date(now.getTime() + STALE_CLAIM_MS - 1000))).toBeNull();

    const late = new Date(now.getTime() + STALE_CLAIM_MS + 1000);
    expect(await q.claim(late)).toMatchObject({ id: stranded.id, status: 'running', attempts: 2 });
    expect((await q.get(done.id))?.status).toBe('done'); // never resurrected
  });

  it('complete/fail apply only to a job the caller still holds', async () => {
    // Two workers overlap, the reaper re-hands the job out, and the original
    // holder finally answers. Its write must not land: 'done' -> 'pending' is
    // a silent third execution of an already-delivered email.
    const q = makeQueue();
    const now = new Date();
    const job = await q.enqueue('t', {}, { runAt: now });

    const c = await q.claim(now);
    await q.complete(job.id, c!.claimedAt!);
    await q.fail(job.id, 'straggler', now, c!.claimedAt!); // late failure from the old holder
    expect(await q.get(job.id)).toMatchObject({ status: 'done', lastError: null });

    // ...and the mirror image: a late complete() on a job already failed back
    // to pending must not mark it done.
    const second = await q.enqueue('t', {}, { runAt: now });
    const c2 = await q.claim(now);
    await q.fail(second.id, 'boom', now, c2!.claimedAt!);
    await q.complete(second.id, c2!.claimedAt!);
    expect((await q.get(second.id))?.status).toBe('pending');
  });

  it('complete/fail are scoped to the claim they came from, not merely to `running`', async () => {
    // The straggler-vs-live-peer race the `status = running` guard alone misses:
    // A stalls past the stale window, the reaper hands the job to B, then A
    // answers. The row IS running — but it is B's run. A's late fail() would
    // requeue a job B is mid-way through (a third delivery of the same email),
    // and A's late complete() would swallow B's genuine failure.
    const q = makeQueue();
    const now = new Date();
    const job = await q.enqueue('t', {}, { maxAttempts: 5, runAt: now });

    const a = await q.claim(now);
    const late = new Date(now.getTime() + STALE_CLAIM_MS + 1000);
    const b = await q.claim(late);
    expect(b?.id).toBe(job.id);

    await q.fail(job.id, 'straggler', late, a!.claimedAt!);
    expect(await q.get(job.id)).toMatchObject({ status: 'running', attempts: 2, lastError: null });

    // B still holds the claim, so B's terminal write lands.
    await q.complete(job.id, b!.claimedAt!);
    expect((await q.get(job.id))?.status).toBe('done');
  });

  it('claim: stale reaping is capped by maxAttempts and dead-letters instead of redelivering forever', async () => {
    // Each reap spends an attempt. Without the cap, a handler that always
    // outlives the window — or a worker crash-looping on a poison payload —
    // is re-handed out every 5 minutes forever, with no dead-letter.
    const q = makeQueue();
    const now = new Date();
    const job = await q.enqueue('t', {}, { maxAttempts: 2, runAt: now });
    const stale = (t: Date): Date => new Date(t.getTime() + STALE_CLAIM_MS + 1000);

    expect((await q.claim(now))?.attempts).toBe(1);
    const second = stale(now);
    expect((await q.claim(second))?.attempts).toBe(2);

    expect(await q.claim(stale(second))).toBeNull();
    expect(await q.get(job.id)).toMatchObject({ status: 'dead', attempts: 2, lastError: STALE_CLAIM_ERROR });
    expect((await q.listByStatus('dead')).map((j) => j.id)).toEqual([job.id]);
  });

  it('listByStatus: partitions the queue', async () => {
    const q = makeQueue();
    const now = new Date();
    const a = await q.enqueue('t', {}, { runAt: now });
    const b = await q.enqueue('t', {}, { runAt: now });
    await q.enqueue('t', {}, { runAt: new Date(now.getTime() + 60_000) });

    const ca = await q.claim(now);
    expect(ca?.id).toBe(a.id);
    await q.complete(a.id, ca!.claimedAt!);
    await q.claim(now); // b is running

    expect((await q.listByStatus('done')).map((j) => j.id)).toEqual([a.id]);
    expect((await q.listByStatus('running')).map((j) => j.id)).toEqual([b.id]);
    expect(await q.listByStatus('pending')).toHaveLength(1);
    expect(await q.listByStatus('dead')).toEqual([]);
  });
}
