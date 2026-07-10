import { describe, expect, it } from 'vitest';
import { memoryStore } from '../src/store/memory.js';

describe('memory store sweep', () => {
  it('removes expired sessions and used/expired tokens, keeps live ones', async () => {
    const store = memoryStore();
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
});
