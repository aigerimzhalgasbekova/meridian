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
      secureCookies: process.env['NODE_ENV'] === 'production',
    },
    now: () => new Date(),
  };

  const mail = outboxTransport(process.env['OUTBOX_DIR'] ?? join(process.cwd(), 'outbox'));
  const worker = new Worker(queue, jobHandlers(mail), {
    onError: (job, err) => console.error(`[worker] job ${job.id} (${job.type}) failed:`, err),
  });
  worker.start();

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
    worker.stop();
    server.close(() => process.exit(0));
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);
}

void main();
