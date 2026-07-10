import type { Job, JobQueue } from './types.js';

export type JobHandler = (job: Job) => Promise<void>;

export interface WorkerOptions {
  pollIntervalMs?: number;
  now?: () => Date;
  onError?: (job: Job, err: unknown) => void;
}

/**
 * Polling worker. Handlers must be idempotent: a job that crashes after a
 * side effect will be retried, so effects are keyed by job id (e.g. the email
 * transport writes outbox/<job.id>.json — a retry overwrites, never duplicates).
 */
export class Worker {
  private timer: NodeJS.Timeout | null = null;
  private stopped = true;

  constructor(
    private readonly queue: JobQueue,
    private readonly handlers: Record<string, JobHandler>,
    private readonly opts: WorkerOptions = {},
  ) {}

  start(): void {
    this.stopped = false;
    const poll = async () => {
      if (this.stopped) return;
      await this.tick();
      if (!this.stopped) this.timer = setTimeout(poll, this.opts.pollIntervalMs ?? 500);
    };
    void poll();
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearTimeout(this.timer);
  }

  /** Drain everything currently eligible. Used by tests and graceful shutdown. */
  async tick(): Promise<number> {
    let processed = 0;
    for (;;) {
      const now = (this.opts.now ?? (() => new Date()))();
      const job = await this.queue.claim(now);
      if (!job) return processed;
      processed++;
      const handler = this.handlers[job.type];
      try {
        if (!handler) throw new Error(`no handler for job type "${job.type}"`);
        await handler(job);
        await this.queue.complete(job.id);
      } catch (err) {
        this.opts.onError?.(job, err);
        await this.queue.fail(job.id, err instanceof Error ? err.message : String(err), now);
      }
    }
  }
}
