import { randomUUID } from 'node:crypto';
import type {
  OneTimeToken,
  RecoveryCode,
  Session,
  Store,
  TokenPurpose,
  User,
} from './types.js';

export function memoryStore(): Store {
  const users = new Map<string, User>();
  const sessions = new Map<string, Session>();
  const tokens = new Map<string, OneTimeToken>();
  const codes: RecoveryCode[] = [];

  return {
    users: {
      async create(u) {
        const user: User = { ...u, id: randomUUID(), createdAt: new Date() };
        users.set(user.id, user);
        return { ...user };
      },
      async findByEmail(email) {
        for (const u of users.values()) if (u.email === email) return { ...u };
        return null;
      },
      async findById(id) {
        const u = users.get(id);
        return u ? { ...u } : null;
      },
      async update(id, patch) {
        const u = users.get(id);
        if (u) Object.assign(u, patch);
      },
      async advanceTotpCounter(id, counter) {
        // Single synchronous check-and-set: no await between compare and write,
        // so concurrent requests cannot interleave (mirrors the SQL guard).
        const u = users.get(id);
        if (!u) return false;
        if (u.totpLastCounter !== null && BigInt(counter) <= BigInt(u.totpLastCounter)) return false;
        u.totpLastCounter = counter;
        return true;
      },
    },
    sessions: {
      async create(s) {
        sessions.set(s.idHash, { ...s });
      },
      async findByIdHash(idHash) {
        const s = sessions.get(idHash);
        return s ? { ...s } : null;
      },
      async update(idHash, patch) {
        const s = sessions.get(idHash);
        if (s) Object.assign(s, patch);
      },
      async delete(idHash) {
        sessions.delete(idHash);
      },
      async deleteAllForUser(userId) {
        for (const [k, s] of sessions) if (s.userId === userId) sessions.delete(k);
      },
      async listForUser(userId) {
        return [...sessions.values()].filter((s) => s.userId === userId).map((s) => ({ ...s }));
      },
    },
    tokens: {
      async create(t) {
        const token: OneTimeToken = { ...t, id: randomUUID(), usedAt: null, createdAt: new Date() };
        tokens.set(token.id, token);
        return { ...token };
      },
      async findActiveByHash(tokenHash: string, purpose: TokenPurpose, now: Date) {
        for (const t of tokens.values()) {
          if (t.tokenHash === tokenHash && t.purpose === purpose && !t.usedAt && t.expiresAt > now) {
            return { ...t };
          }
        }
        return null;
      },
      async markUsed(id, now) {
        const t = tokens.get(id);
        if (!t || t.usedAt) return false;
        t.usedAt = now;
        return true;
      },
      async revokeAllForUser(userId, purpose) {
        for (const t of tokens.values()) {
          if (t.userId === userId && t.purpose === purpose && !t.usedAt) t.usedAt = new Date();
        }
      },
    },
    recoveryCodes: {
      async replaceForUser(userId, codeHashes) {
        for (let i = codes.length - 1; i >= 0; i--) if (codes[i]!.userId === userId) codes.splice(i, 1);
        for (const h of codeHashes) codes.push({ userId, codeHash: h, usedAt: null });
      },
      async consume(userId, codeHash) {
        const c = codes.find((c) => c.userId === userId && c.codeHash === codeHash && !c.usedAt);
        if (!c) return false;
        c.usedAt = new Date();
        return true;
      },
      async countUnused(userId) {
        return codes.filter((c) => c.userId === userId && !c.usedAt).length;
      },
    },
    async sweep(now) {
      let removed = 0;
      for (const [k, s] of sessions) {
        if (s.expiresAt < now) {
          sessions.delete(k);
          removed++;
        }
      }
      for (const [k, t] of tokens) {
        if (t.expiresAt < now || t.usedAt) {
          tokens.delete(k);
          removed++;
        }
      }
      return removed;
    },
  };
}
