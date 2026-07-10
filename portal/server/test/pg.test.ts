// Postgres integration tests. Skipped unless TEST_DATABASE_URL is set, e.g.:
//   TEST_DATABASE_URL=postgres://localhost/portal_test npm test
//
// The bulk of the coverage is the shared contract the memory implementations
// also run (test/contract/) — that is what keeps the two backends honest. What
// stays here is what only a real database can show: concurrent workers
// contending for the same row.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import pg from 'pg';
import { postgresStore } from '../src/store/postgres.js';
import { postgresQueue } from '../src/queue/postgres.js';
import { runStoreContract } from './contract/store.js';
import { runQueueContract } from './contract/queue.js';

const url = process.env['TEST_DATABASE_URL'];

// CI's integration job sets REQUIRE_TEST_DATABASE_URL. Skipping is the right
// default locally, but a suite that skips when the database service disappears
// is a suite that stops protecting anything without ever going red.
if (process.env['REQUIRE_TEST_DATABASE_URL'] && !url) {
  throw new Error('REQUIRE_TEST_DATABASE_URL is set but TEST_DATABASE_URL is empty');
}

describe.skipIf(!url)('postgres store + queue (integration)', () => {
  let pool: pg.Pool;

  beforeAll(async () => {
    pool = new pg.Pool({ connectionString: url });
    await pool.query(readFileSync(join(import.meta.dirname, '../schema.sql'), 'utf8'));
  });

  // Each contract test expects a clean store, which truncation provides.
  beforeEach(async () => {
    await pool.query('TRUNCATE users, sessions, one_time_tokens, recovery_codes, jobs CASCADE');
  });

  afterAll(async () => {
    await pool?.end();
  });

  describe('store contract', () => {
    runStoreContract(() => postgresStore(pool));
  });

  describe('queue contract', () => {
    runQueueContract(() => postgresQueue(pool));
  });

  it('SKIP LOCKED: concurrent claimers on separate connections get distinct jobs', async () => {
    const q = postgresQueue(pool);
    const now = new Date();
    // runAt must be pinned to `now`: the default is new Date() at enqueue
    // time, which lands after `now` and makes claim(now) skip the job.
    for (let i = 0; i < 10; i++) await q.enqueue('t', { i }, { runAt: now });
    const claims = await Promise.all(Array.from({ length: 10 }, () => q.claim(now)));
    const ids = claims.filter((j) => j !== null).map((j) => j!.id);
    expect(ids).toHaveLength(10);
    expect(new Set(ids).size).toBe(10);
    expect(await q.claim(now)).toBeNull();
  });
});
