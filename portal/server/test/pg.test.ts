// Postgres integration tests. Skipped unless TEST_DATABASE_URL is set, e.g.:
//   TEST_DATABASE_URL=postgres://localhost/portal_test npm test
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import pg from 'pg';
import { postgresStore } from '../src/store/postgres.js';
import { postgresQueue } from '../src/queue/postgres.js';
import { backoffMs } from '../src/queue/types.js';

const url = process.env['TEST_DATABASE_URL'];

describe.skipIf(!url)('postgres store + queue (integration)', () => {
  let pool: pg.Pool;

  beforeAll(async () => {
    pool = new pg.Pool({ connectionString: url });
    await pool.query(readFileSync(join(import.meta.dirname, '../schema.sql'), 'utf8'));
  });

  beforeEach(async () => {
    await pool.query('TRUNCATE users, sessions, one_time_tokens, recovery_codes, jobs CASCADE');
  });

  afterAll(async () => {
    await pool?.end();
  });

  it('user / session / token / recovery-code round trip', async () => {
    const store = postgresStore(pool);
    const user = await store.users.create({
      email: 'pg@example.com',
      emailVerified: false,
      pendingEmail: null,
      passwordHash: 'hash',
      totpSecret: null,
      totpPendingSecret: null,
      totpLastCounter: null,
    });
    await store.users.update(user.id, { emailVerified: true, totpLastCounter: '123456789012345678' });
    const fetched = await store.users.findByEmail('pg@example.com');
    expect(fetched).toMatchObject({ id: user.id, emailVerified: true, totpLastCounter: '123456789012345678' });

    const now = new Date();
    await store.sessions.create({
      idHash: 'h1',
      userId: user.id,
      csrfToken: 'c',
      mfaPending: true,
      createdAt: now,
      expiresAt: new Date(now.getTime() + 1000),
    });
    await store.sessions.update('h1', { mfaPending: false });
    expect((await store.sessions.findByIdHash('h1'))?.mfaPending).toBe(false);
    expect(await store.sessions.listForUser(user.id)).toHaveLength(1);
    await store.sessions.deleteAllForUser(user.id);
    expect(await store.sessions.findByIdHash('h1')).toBeNull();

    const tok = await store.tokens.create({
      userId: user.id,
      purpose: 'password_reset',
      tokenHash: 't1',
      payload: null,
      expiresAt: new Date(now.getTime() + 1000),
    });
    expect(await store.tokens.findActiveByHash('t1', 'password_reset', now)).not.toBeNull();
    expect(await store.tokens.markUsed(tok.id, now)).toBe(true);
    expect(await store.tokens.markUsed(tok.id, now)).toBe(false); // single use, atomically
    expect(await store.tokens.findActiveByHash('t1', 'password_reset', now)).toBeNull();

    await store.recoveryCodes.replaceForUser(user.id, ['a', 'b']);
    expect(await store.recoveryCodes.consume(user.id, 'a')).toBe(true);
    expect(await store.recoveryCodes.consume(user.id, 'a')).toBe(false);
    expect(await store.recoveryCodes.countUnused(user.id)).toBe(1);
  });

  it('advanceTotpCounter: monotonic, rejects replays and stale counters', async () => {
    const store = postgresStore(pool);
    const user = await store.users.create({
      email: 'totp@example.com',
      emailVerified: true,
      pendingEmail: null,
      passwordHash: 'hash',
      totpSecret: 'sealed',
      totpPendingSecret: null,
      totpLastCounter: null,
    });
    expect(await store.users.advanceTotpCounter(user.id, '100')).toBe(true);
    expect(await store.users.advanceTotpCounter(user.id, '100')).toBe(false); // replay
    expect(await store.users.advanceTotpCounter(user.id, '99')).toBe(false); // stale
    expect(await store.users.advanceTotpCounter(user.id, '101')).toBe(true);
    expect((await store.users.findById(user.id))?.totpLastCounter).toBe('101');
  });

  it('sweep: removes expired sessions and used/expired tokens, keeps live ones', async () => {
    const store = postgresStore(pool);
    const user = await store.users.create({
      email: 'sweep@example.com',
      emailVerified: false,
      pendingEmail: null,
      passwordHash: 'hash',
      totpSecret: null,
      totpPendingSecret: null,
      totpLastCounter: null,
    });
    const now = new Date();
    await store.sessions.create({
      idHash: 'expired',
      userId: user.id,
      csrfToken: 'c',
      mfaPending: false,
      createdAt: now,
      expiresAt: new Date(now.getTime() - 1000),
    });
    await store.sessions.create({
      idHash: 'live',
      userId: user.id,
      csrfToken: 'c',
      mfaPending: false,
      createdAt: now,
      expiresAt: new Date(now.getTime() + 60_000),
    });
    const usedTok = await store.tokens.create({
      userId: user.id,
      purpose: 'password_reset',
      tokenHash: 'used',
      payload: null,
      expiresAt: new Date(now.getTime() + 60_000),
    });
    await store.tokens.markUsed(usedTok.id, now);
    await store.tokens.create({
      userId: user.id,
      purpose: 'verify_email',
      tokenHash: 'live-token',
      payload: null,
      expiresAt: new Date(now.getTime() + 60_000),
    });

    const removed = await store.sweep(now);
    expect(removed).toBe(2); // expired session + used token

    expect(await store.sessions.findByIdHash('expired')).toBeNull();
    expect(await store.sessions.findByIdHash('live')).not.toBeNull();
    expect(await store.tokens.findActiveByHash('used', 'password_reset', now)).toBeNull();
    expect(await store.tokens.findActiveByHash('live-token', 'verify_email', now)).not.toBeNull();
  });

  it('queue: claim, retry with backoff, dead-letter', async () => {
    const q = postgresQueue(pool);
    const now = new Date();
    const job = await q.enqueue('t', { n: 1 }, { maxAttempts: 2, runAt: now });

    const claimed = await q.claim(now);
    expect(claimed?.id).toBe(job.id);
    expect(claimed?.attempts).toBe(1);
    expect(await q.claim(now)).toBeNull(); // running job is invisible

    await q.fail(job.id, 'boom', now);
    expect(await q.claim(now)).toBeNull(); // backed off into the future
    const later = new Date(now.getTime() + backoffMs(1) + 1000);
    const again = await q.claim(later);
    expect(again?.attempts).toBe(2);

    await q.fail(job.id, 'boom again', later);
    expect((await q.get(job.id))?.status).toBe('dead');
    expect(await q.listByStatus('dead')).toHaveLength(1);
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
