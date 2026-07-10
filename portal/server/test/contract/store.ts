// Shared conformance suite for Store implementations. memory runs it on every
// `npm test`; postgres runs it when TEST_DATABASE_URL is set.
//
// It exists because the API tests all run against the memory store, so postgres
// can diverge silently — and the divergences that matter are the ones the
// database enforces and a Map does not (unique email, foreign keys).
//
// Callers supply a factory returning a *clean* store per test: memoryStore()
// is fresh per call, and the postgres suite truncates in beforeEach.
//
// Deliberately not asserted, because the backends legitimately differ:
//   - listForUser order (postgres sorts by created_at, memory by insertion).
//   - Duplicate session idHash / token hash. Both are SHA-256 of high-entropy
//     random values, so collision is not a reachable state; postgres rejects on
//     its primary key, memory would overwrite.
import { randomUUID } from 'node:crypto';
import { expect, it } from 'vitest';
import type { Store, User } from '../../src/store/types.js';

function newUser(store: Store, email = 'a@example.test'): Promise<User> {
  return store.users.create({
    email,
    emailVerified: false,
    pendingEmail: null,
    passwordHash: 'hash',
    totpSecret: null,
    totpPendingSecret: null,
    totpLastCounter: null,
  });
}

export function runStoreContract(makeStore: () => Store): void {
  // --- users ---

  it('users: create round-trips and is findable by id and email', async () => {
    const store = makeStore();
    const user = await newUser(store);
    expect(user.id).toBeTruthy();
    expect(user.createdAt).toBeInstanceOf(Date);

    expect(await store.users.findById(user.id)).toMatchObject({ id: user.id, email: 'a@example.test' });
    expect(await store.users.findByEmail('a@example.test')).toMatchObject({ id: user.id });
  });

  it('users: lookups miss cleanly', async () => {
    const store = makeStore();
    // A well-formed but absent UUID: postgres types the id column, so a
    // non-UUID string would fail on parse rather than miss.
    expect(await store.users.findById(randomUUID())).toBeNull();
    expect(await store.users.findByEmail('nobody@example.test')).toBeNull();
  });

  it('users: a duplicate email is rejected', async () => {
    const store = makeStore();
    await newUser(store, 'dup@example.test');
    // Signup does findByEmail-then-create, so this constraint is what actually
    // stops two concurrent signups from both creating the same account.
    await expect(newUser(store, 'dup@example.test')).rejects.toThrow();
  });

  it('users: update applies a partial patch and ignores unknown ids', async () => {
    const store = makeStore();
    const user = await newUser(store);
    await store.users.update(user.id, { emailVerified: true, pendingEmail: 'new@example.test' });
    expect(await store.users.findById(user.id)).toMatchObject({
      emailVerified: true,
      pendingEmail: 'new@example.test',
      passwordHash: 'hash', // untouched by the patch
    });

    await store.users.update(user.id, { totpSecret: 'sealed', totpPendingSecret: null });
    expect((await store.users.findById(user.id))?.totpSecret).toBe('sealed');

    await expect(store.users.update(randomUUID(), { emailVerified: true })).resolves.toBeUndefined();
  });

  it('users: advanceTotpCounter is monotonic and rejects replays and stale counters', async () => {
    const store = makeStore();
    const user = await newUser(store);
    expect(await store.users.advanceTotpCounter(user.id, '100')).toBe(true);
    expect(await store.users.advanceTotpCounter(user.id, '100')).toBe(false); // replay
    expect(await store.users.advanceTotpCounter(user.id, '99')).toBe(false); // stale
    expect(await store.users.advanceTotpCounter(user.id, '101')).toBe(true);
    expect((await store.users.findById(user.id))?.totpLastCounter).toBe('101');

    // Counters exceed 2^53, so they are compared as bigints, not floats.
    expect(await store.users.advanceTotpCounter(user.id, '9007199254740993')).toBe(true);
    expect(await store.users.advanceTotpCounter(user.id, '9007199254740992')).toBe(false);

    expect(await store.users.advanceTotpCounter(randomUUID(), '1')).toBe(false);
  });

  // --- sessions ---

  it('sessions: create, find, update, delete', async () => {
    const store = makeStore();
    const user = await newUser(store);
    const now = new Date();
    await store.sessions.create({
      idHash: 'h1', userId: user.id, csrfToken: 'c', mfaPending: true,
      createdAt: now, expiresAt: new Date(now.getTime() + 60_000),
    });

    const got = await store.sessions.findByIdHash('h1');
    expect(got).toMatchObject({ idHash: 'h1', userId: user.id, csrfToken: 'c', mfaPending: true });
    expect(got?.expiresAt.getTime()).toBe(now.getTime() + 60_000);

    await store.sessions.update('h1', { mfaPending: false });
    expect((await store.sessions.findByIdHash('h1'))?.mfaPending).toBe(false);

    const newExpiry = new Date(now.getTime() + 120_000);
    await store.sessions.update('h1', { expiresAt: newExpiry });
    expect((await store.sessions.findByIdHash('h1'))?.expiresAt.getTime()).toBe(newExpiry.getTime());

    expect(await store.sessions.findByIdHash('nope')).toBeNull();
    await store.sessions.delete('h1');
    expect(await store.sessions.findByIdHash('h1')).toBeNull();
    // Deleting an absent session is a no-op, not an error.
    await expect(store.sessions.delete('h1')).resolves.toBeUndefined();
  });

  it('sessions: listForUser and deleteAllForUser are scoped to one user', async () => {
    const store = makeStore();
    const alice = await newUser(store, 'alice@example.test');
    const bob = await newUser(store, 'bob@example.test');
    const now = new Date();
    const mk = (idHash: string, userId: string) =>
      store.sessions.create({
        idHash, userId, csrfToken: 'c', mfaPending: false,
        createdAt: now, expiresAt: new Date(now.getTime() + 60_000),
      });
    await mk('a1', alice.id);
    await mk('a2', alice.id);
    await mk('b1', bob.id);

    const listed = await store.sessions.listForUser(alice.id);
    expect(listed.map((s) => s.idHash).sort()).toEqual(['a1', 'a2']);
    expect(await store.sessions.listForUser(randomUUID())).toEqual([]);

    await store.sessions.deleteAllForUser(alice.id);
    expect(await store.sessions.listForUser(alice.id)).toEqual([]);
    expect(await store.sessions.listForUser(bob.id)).toHaveLength(1);
    await expect(store.sessions.deleteAllForUser(randomUUID())).resolves.toBeUndefined();
  });

  // --- one-time tokens ---

  it('tokens: findActiveByHash is scoped by purpose, expiry, and use', async () => {
    const store = makeStore();
    const user = await newUser(store);
    const now = new Date();
    const tok = await store.tokens.create({
      userId: user.id, purpose: 'password_reset', tokenHash: 't1',
      payload: null, expiresAt: new Date(now.getTime() + 60_000),
    });
    expect(tok.usedAt).toBeNull();
    expect(tok.id).toBeTruthy();

    expect(await store.tokens.findActiveByHash('t1', 'password_reset', now)).toMatchObject({ id: tok.id });
    expect(await store.tokens.findActiveByHash('t1', 'verify_email', now)).toBeNull(); // wrong purpose
    expect(await store.tokens.findActiveByHash('nope', 'password_reset', now)).toBeNull();
    // Expired: an instant past expiresAt no longer matches.
    expect(await store.tokens.findActiveByHash('t1', 'password_reset', new Date(now.getTime() + 120_000))).toBeNull();
  });

  it('tokens: markUsed is single-use', async () => {
    const store = makeStore();
    const user = await newUser(store);
    const now = new Date();
    const tok = await store.tokens.create({
      userId: user.id, purpose: 'verify_email', tokenHash: 't1',
      payload: 'new@example.test', expiresAt: new Date(now.getTime() + 60_000),
    });
    expect(tok.payload).toBe('new@example.test');

    expect(await store.tokens.markUsed(tok.id, now)).toBe(true);
    expect(await store.tokens.markUsed(tok.id, now)).toBe(false); // atomically single-use
    expect(await store.tokens.findActiveByHash('t1', 'verify_email', now)).toBeNull();
    expect(await store.tokens.markUsed(randomUUID(), now)).toBe(false);
  });

  it('tokens: revokeAllForUser only burns the named purpose', async () => {
    const store = makeStore();
    const user = await newUser(store);
    const now = new Date();
    const exp = new Date(now.getTime() + 60_000);
    await store.tokens.create({ userId: user.id, purpose: 'password_reset', tokenHash: 'r1', payload: null, expiresAt: exp });
    await store.tokens.create({ userId: user.id, purpose: 'password_reset', tokenHash: 'r2', payload: null, expiresAt: exp });
    await store.tokens.create({ userId: user.id, purpose: 'verify_email', tokenHash: 'v1', payload: null, expiresAt: exp });

    await store.tokens.revokeAllForUser(user.id, 'password_reset');
    expect(await store.tokens.findActiveByHash('r1', 'password_reset', now)).toBeNull();
    expect(await store.tokens.findActiveByHash('r2', 'password_reset', now)).toBeNull();
    expect(await store.tokens.findActiveByHash('v1', 'verify_email', now)).not.toBeNull();
    await expect(store.tokens.revokeAllForUser(randomUUID(), 'password_reset')).resolves.toBeUndefined();
  });

  // --- recovery codes ---

  it('recoveryCodes: consume is single-use and replaceForUser clears the old set', async () => {
    const store = makeStore();
    const user = await newUser(store);

    await store.recoveryCodes.replaceForUser(user.id, ['a', 'b', 'c']);
    expect(await store.recoveryCodes.countUnused(user.id)).toBe(3);

    expect(await store.recoveryCodes.consume(user.id, 'a')).toBe(true);
    expect(await store.recoveryCodes.consume(user.id, 'a')).toBe(false); // already used
    expect(await store.recoveryCodes.consume(user.id, 'zzz')).toBe(false); // unknown
    expect(await store.recoveryCodes.countUnused(user.id)).toBe(2);

    // Regenerating invalidates every previous code, used or not.
    await store.recoveryCodes.replaceForUser(user.id, ['d']);
    expect(await store.recoveryCodes.countUnused(user.id)).toBe(1);
    expect(await store.recoveryCodes.consume(user.id, 'b')).toBe(false);
    expect(await store.recoveryCodes.consume(user.id, 'd')).toBe(true);

    expect(await store.recoveryCodes.countUnused(randomUUID())).toBe(0);
  });

  it('recoveryCodes: codes are scoped to their owner', async () => {
    const store = makeStore();
    const alice = await newUser(store, 'alice@example.test');
    const bob = await newUser(store, 'bob@example.test');
    await store.recoveryCodes.replaceForUser(alice.id, ['shared']);
    await store.recoveryCodes.replaceForUser(bob.id, ['shared']);

    expect(await store.recoveryCodes.consume(alice.id, 'shared')).toBe(true);
    expect(await store.recoveryCodes.countUnused(bob.id)).toBe(1);
  });

  // --- sweep ---

  it('sweep: removes expired sessions and used/expired tokens, keeps live ones', async () => {
    const store = makeStore();
    const user = await newUser(store);
    const now = new Date();
    const past = new Date(now.getTime() - 1000);
    const future = new Date(now.getTime() + 60_000);

    const mkSession = (idHash: string, expiresAt: Date) =>
      store.sessions.create({ idHash, userId: user.id, csrfToken: 'c', mfaPending: false, createdAt: now, expiresAt });
    await mkSession('expired', past);
    await mkSession('live', future);

    const used = await store.tokens.create({
      userId: user.id, purpose: 'password_reset', tokenHash: 'used', payload: null, expiresAt: future,
    });
    await store.tokens.markUsed(used.id, now);
    await store.tokens.create({
      userId: user.id, purpose: 'password_reset', tokenHash: 'expired-token', payload: null, expiresAt: past,
    });
    await store.tokens.create({
      userId: user.id, purpose: 'verify_email', tokenHash: 'live-token', payload: null, expiresAt: future,
    });

    // expired session + used token + expired token
    expect(await store.sweep(now)).toBe(3);

    expect(await store.sessions.findByIdHash('expired')).toBeNull();
    expect(await store.sessions.findByIdHash('live')).not.toBeNull();
    expect(await store.tokens.findActiveByHash('live-token', 'verify_email', now)).not.toBeNull();

    // A second sweep with nothing left to reclaim is a no-op.
    expect(await store.sweep(now)).toBe(0);
  });
}
