// Entry point. In-memory store + outbox mail by default (demo mode);
// set DATABASE_URL to run against Postgres (apply schema.sql first).
import { existsSync } from 'node:fs';
import { join } from 'node:path';
import express from 'express';
import { defaultConfig, type AppContext } from './context.js';
import { createApp } from './app.js';
import { memoryStore } from './store/memory.js';
import { memoryQueue } from './queue/memory.js';
import { jobHandlers } from './jobs/handlers.js';
import { outboxTransport } from './mail/transport.js';
import { Worker } from './queue/worker.js';

const port = Number(process.env['PORT'] ?? 3000);
const databaseUrl = process.env['DATABASE_URL'];

function loadTotpKek(): Buffer {
  const env = process.env['PORTAL_TOTP_KEK'];
  if (env) {
    const key = Buffer.from(env, 'base64');
    if (key.length !== 32) throw new Error('PORTAL_TOTP_KEK must be 32 bytes (base64-encoded)');
    return key;
  }
  // Refuse to protect a real database with the in-code placeholder key.
  if (databaseUrl) throw new Error('PORTAL_TOTP_KEK is required when DATABASE_URL is set');
  return defaultConfig.totpKek;
}

async function main(): Promise<void> {
  let store, queue;
  if (databaseUrl) {
    const { default: pg } = await import('pg');
    const pool = new pg.Pool({ connectionString: databaseUrl });
    const { postgresStore } = await import('./store/postgres.js');
    const { postgresQueue } = await import('./queue/postgres.js');
    store = postgresStore(pool);
    queue = postgresQueue(pool);
  } else {
    store = memoryStore();
    queue = memoryQueue();
  }

  const ctx: AppContext = {
    store,
    queue,
    config: {
      ...defaultConfig,
      baseUrl: process.env['BASE_URL'] ?? defaultConfig.baseUrl,
      // Default (secure) wins unless dev opts out explicitly; an unset or
      // misspelled NODE_ENV must not silently downgrade to insecure cookies.
      secureCookies: process.env['NODE_ENV'] === 'development' ? false : defaultConfig.secureCookies,
      totpKek: loadTotpKek(),
    },
    now: () => new Date(),
  };

  const mail = outboxTransport(process.env['OUTBOX_DIR'] ?? join(process.cwd(), 'outbox'));
  const worker = new Worker(queue, jobHandlers(mail), {
    onError: (job, err) => console.error(`[worker] job ${job.id} (${job.type}) failed:`, err),
  });
  worker.start();

  // Reap expired sessions and used/expired one-time tokens hourly. Nothing
  // reads them again, so unswept they only bloat the tables (mirrors idp's
  // sweep). Tracks the in-flight run so shutdown can await it.
  let sweeping: Promise<unknown> = Promise.resolve();
  const sweepTimer = setInterval(() => {
    sweeping = store.sweep(new Date()).catch((err) => console.error('[sweep] failed:', err));
  }, 60 * 60 * 1000);

  const app = createApp(ctx);

  // Serve the built frontend when present (the Docker image); dev uses Vite.
  const webDist = process.env['WEB_DIST'] ?? join(process.cwd(), 'web/dist');
  if (existsSync(webDist)) {
    app.use(express.static(webDist));
    app.get(/^\/(?!api\/).*/, (_req, res) => res.sendFile(join(webDist, 'index.html')));
  }

  const server = app.listen(port, () => {
    console.log(`portal server on http://localhost:${port} (${databaseUrl ? 'postgres' : 'in-memory'} store, outbox mail)`);
  });

  const shutdown = () => {
    clearInterval(sweepTimer);
    // Await the in-flight tick/sweep so a mid-job deploy never strands work.
    void Promise.all([worker.stop(), sweeping]).then(() => server.close(() => process.exit(0)));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

void main();
