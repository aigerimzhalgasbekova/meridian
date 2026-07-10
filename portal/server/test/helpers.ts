import type { Express } from 'express';
import { createApp } from '../src/app.js';
import { defaultConfig, type AppContext } from '../src/context.js';
import { memoryQueue } from '../src/queue/memory.js';
import { memoryStore } from '../src/store/memory.js';
import { Worker } from '../src/queue/worker.js';
import { jobHandlers } from '../src/jobs/handlers.js';
import { memoryTransport } from '../src/mail/transport.js';
import type { Email } from '../src/mail/transport.js';

export interface TestApp {
  app: Express;
  ctx: AppContext;
  clock: { now: Date; advance(ms: number): void };
  /** Drain the queue and return every mail sent so far (keyed by job id). */
  drainMail(): Promise<Email[]>;
  /** Last URL token in the last email (reset / verify links). */
  lastToken(): Promise<string>;
}

export function testApp(): TestApp {
  const clock = {
    now: new Date('2026-07-09T12:00:00Z'),
    advance(ms: number) {
      this.now = new Date(this.now.getTime() + ms);
    },
  };
  const ctx: AppContext = {
    store: memoryStore(),
    queue: memoryQueue(),
    config: {
      ...defaultConfig,
      uniformDelayMs: 50,
      rateLimit: { limit: 1000, windowMs: 60_000 },
      // Tests run over plain http; explicit opt-out, not a weakened default.
      secureCookies: false,
    },
    now: () => clock.now,
  };
  const mail = memoryTransport();
  const worker = new Worker(ctx.queue, jobHandlers(mail), { now: ctx.now });

  return {
    app: createApp(ctx),
    ctx,
    clock,
    async drainMail() {
      await worker.tick();
      return [...mail.sent.values()];
    },
    async lastToken() {
      await worker.tick();
      const emails = [...mail.sent.values()];
      const text = emails[emails.length - 1]!.text;
      const m = /token=([A-Za-z0-9_-]+)/.exec(text);
      if (!m) throw new Error(`no token link in email: ${text}`);
      return m[1]!;
    },
  };
}

/** Extract the portal_session cookie value from a supertest response. */
export function sessionCookieOf(res: { headers: Record<string, unknown> }): string {
  const raw = res.headers['set-cookie'];
  const arr = Array.isArray(raw) ? raw : [raw];
  const cookie = arr.find((c) => typeof c === 'string' && c.startsWith('portal_session='));
  if (typeof cookie !== 'string') throw new Error('no session cookie set');
  return cookie.split(';')[0]!;
}
