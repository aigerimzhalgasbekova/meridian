import type { Job, JobQueue } from './types.js';

export type JobHandler = (job: Job) => Promise<void>;

export interface WorkerOptions {
  pollIntervalMs?: number;
  now?: () => Date;
  /** Handler failures — the job itself threw. */
  onError?: (job: Job, err: unknown) => void;
  /** Poll-loop failures: claim(), or complete()/fail() bookkeeping. Distinct
   * from onError because a bookkeeping failure says nothing about the job. */
  onPollError?: (err: unknown) => void;
}

/**
 * Polling worker. Handlers must be idempotent: a job that crashes after a
 * side effect will be retried, so effects are keyed by job id (e.g. the email
 * transport writes outbox/<job.id>.json — a retry overwrites, never duplicates).
 * ponytail: that dedup is a property of the *dev* outbox transport only. An
 * SES/SMTP transport must carry its own (a sent_messages(job_id) row written
 * with complete(), or an idempotency key) before it ships.
 */
export class Worker {
  private timer: NodeJS.Timeout | null = null;
  private stopped = true;
  private running: Promise<unknown> | null = null;

  constructor(
    private readonly queue: JobQueue,
    private readonly handlers: Record<string, JobHandler>,
    private readonly opts: WorkerOptions = {},
  ) {}

  start(): void {
    this.stopped = false;
    const poll = async () => {
      if (this.stopped) return;
      this.running = this.tick();
      try {
        await this.running;
      } catch (err) {
        // The database being unreachable — a cold boot, an RDS failover — must
        // not become an unhandled rejection: that kills the process and turns a
        // transient blip into a crash-loop. Report it and retry next interval.
        this.reportPollError(err);
      } finally {
        this.running = null;
      }
      if (!this.stopped) this.timer = setTimeout(poll, this.opts.pollIntervalMs ?? 500);
    };
    // No startup requeue: jobs stranded 'running' by a crash (or by a failed
    // complete()/fail()) are reclaimed by claim()'s stale-claim branch, which
    // unlike a blanket requeue does not also yank a peer worker's in-flight
    // job during the two-worker overlap of a rolling deploy.
    void poll();
  }

  private reportPollError(err: unknown): void {
    if (this.opts.onPollError) this.opts.onPollError(err);
    else console.error('worker poll failed', err);
  }

  /** Stop polling and await the currently-running tick so no claimed job is stranded. */
  async stop(): Promise<void> {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
    try {
      await this.running;
    } catch {
      // Already reported by the poll loop; shutdown must still complete.
    }
  }

  /** Drain everything currently eligible. Used by tests and graceful shutdown. */
  async tick(): Promise<number> {
    let processed = 0;
    for (;;) {
      const now = (this.opts.now ?? (() => new Date()))();
      const job = await this.queue.claim(now);
      if (!job) return processed;
      processed++;
      // The stamp of *this* claim: terminal writes are scoped to it, so if the
      // handler outruns STALE_CLAIM_MS and the reaper hands the job to a peer,
      // this worker's late answer is ignored rather than clobbering the peer's.
      // (claim() always sets it; `?? now` is what it set it to.)
      const claimedAt = job.claimedAt ?? now;
      const handler = this.handlers[job.type];
      try {
        if (!handler) throw new Error(`no handler for job type "${job.type}"`);
        await handler(job);
      } catch (err) {
        this.opts.onError?.(job, err);
        await this.queue.fail(job.id, err instanceof Error ? err.message : String(err), now, claimedAt);
        continue;
      }
      // Deliberately outside the try: a complete() that rejects is a database
      // problem, not a handler failure. Treating it as one would call fail(),
      // reschedule a job whose side effect already happened, and run it twice.
      // Left 'running', the stale-claim reaper retries it instead.
      await this.queue.complete(job.id, claimedAt);
    }
  }
}
