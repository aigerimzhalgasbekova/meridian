import type { Pool } from 'pg';
import type { Session, Store, User } from './types.js';

interface UserRow {
  id: string;
  email: string;
  email_verified: boolean;
  pending_email: string | null;
  password_hash: string;
  totp_secret: string | null;
  totp_pending_secret: string | null;
  totp_last_counter: string | null;
  created_at: Date;
}

function toUser(r: UserRow): User {
  return {
    id: r.id,
    email: r.email,
    emailVerified: r.email_verified,
    pendingEmail: r.pending_email,
    passwordHash: r.password_hash,
    totpSecret: r.totp_secret,
    totpPendingSecret: r.totp_pending_secret,
    totpLastCounter: r.totp_last_counter,
    createdAt: r.created_at,
  };
}

const USER_COLS: Record<string, string> = {
  email: 'email',
  emailVerified: 'email_verified',
  pendingEmail: 'pending_email',
  passwordHash: 'password_hash',
  totpSecret: 'totp_secret',
  totpPendingSecret: 'totp_pending_secret',
  totpLastCounter: 'totp_last_counter',
};

export function postgresStore(pool: Pool): Store {
  return {
    users: {
      async create(u) {
        const { rows } = await pool.query<UserRow>(
          `INSERT INTO users (email, email_verified, pending_email, password_hash, totp_secret, totp_pending_secret, totp_last_counter)
           VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
          [u.email, u.emailVerified, u.pendingEmail, u.passwordHash, u.totpSecret, u.totpPendingSecret, u.totpLastCounter],
        );
        return toUser(rows[0]!);
      },
      async findByEmail(email) {
        const { rows } = await pool.query<UserRow>(`SELECT * FROM users WHERE email = $1`, [email]);
        return rows[0] ? toUser(rows[0]) : null;
      },
      async findById(id) {
        const { rows } = await pool.query<UserRow>(`SELECT * FROM users WHERE id = $1`, [id]);
        return rows[0] ? toUser(rows[0]) : null;
      },
      async update(id, patch) {
        const sets: string[] = [];
        const vals: unknown[] = [id];
        for (const [k, v] of Object.entries(patch)) {
          const col = USER_COLS[k];
          if (!col) continue;
          vals.push(v);
          sets.push(`${col} = $${vals.length}`);
        }
        if (sets.length) await pool.query(`UPDATE users SET ${sets.join(', ')} WHERE id = $1`, vals);
      },
    },
    sessions: {
      async create(s) {
        await pool.query(
          `INSERT INTO sessions (id_hash, user_id, csrf_token, mfa_pending, created_at, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6)`,
          [s.idHash, s.userId, s.csrfToken, s.mfaPending, s.createdAt, s.expiresAt],
        );
      },
      async findByIdHash(idHash) {
        const { rows } = await pool.query(`SELECT * FROM sessions WHERE id_hash = $1`, [idHash]);
        const r = rows[0];
        if (!r) return null;
        return {
          idHash: r.id_hash,
          userId: r.user_id,
          csrfToken: r.csrf_token,
          mfaPending: r.mfa_pending,
          createdAt: r.created_at,
          expiresAt: r.expires_at,
        } satisfies Session;
      },
      async update(idHash, patch) {
        if (patch.mfaPending !== undefined) {
          await pool.query(`UPDATE sessions SET mfa_pending = $2 WHERE id_hash = $1`, [idHash, patch.mfaPending]);
        }
        if (patch.expiresAt !== undefined) {
          await pool.query(`UPDATE sessions SET expires_at = $2 WHERE id_hash = $1`, [idHash, patch.expiresAt]);
        }
      },
      async delete(idHash) {
        await pool.query(`DELETE FROM sessions WHERE id_hash = $1`, [idHash]);
      },
      async deleteAllForUser(userId) {
        await pool.query(`DELETE FROM sessions WHERE user_id = $1`, [userId]);
      },
      async listForUser(userId) {
        const { rows } = await pool.query(`SELECT * FROM sessions WHERE user_id = $1 ORDER BY created_at`, [userId]);
        return rows.map((r) => ({
          idHash: r.id_hash,
          userId: r.user_id,
          csrfToken: r.csrf_token,
          mfaPending: r.mfa_pending,
          createdAt: r.created_at,
          expiresAt: r.expires_at,
        }));
      },
    },
    tokens: {
      async create(t) {
        const { rows } = await pool.query(
          `INSERT INTO one_time_tokens (user_id, purpose, token_hash, payload, expires_at)
           VALUES ($1, $2, $3, $4, $5) RETURNING *`,
          [t.userId, t.purpose, t.tokenHash, t.payload, t.expiresAt],
        );
        const r = rows[0];
        return {
          id: r.id,
          userId: r.user_id,
          purpose: r.purpose,
          tokenHash: r.token_hash,
          payload: r.payload,
          expiresAt: r.expires_at,
          usedAt: r.used_at,
          createdAt: r.created_at,
        };
      },
      async findActiveByHash(tokenHash, purpose, now) {
        const { rows } = await pool.query(
          `SELECT * FROM one_time_tokens
           WHERE token_hash = $1 AND purpose = $2 AND used_at IS NULL AND expires_at > $3`,
          [tokenHash, purpose, now],
        );
        const r = rows[0];
        if (!r) return null;
        return {
          id: r.id,
          userId: r.user_id,
          purpose: r.purpose,
          tokenHash: r.token_hash,
          payload: r.payload,
          expiresAt: r.expires_at,
          usedAt: r.used_at,
          createdAt: r.created_at,
        };
      },
      async markUsed(id, now) {
        // Atomic single-use enforcement: the WHERE clause loses the race for us.
        const res = await pool.query(
          `UPDATE one_time_tokens SET used_at = $2 WHERE id = $1 AND used_at IS NULL`,
          [id, now],
        );
        return (res.rowCount ?? 0) > 0;
      },
      async revokeAllForUser(userId, purpose) {
        await pool.query(
          `UPDATE one_time_tokens SET used_at = now() WHERE user_id = $1 AND purpose = $2 AND used_at IS NULL`,
          [userId, purpose],
        );
      },
    },
    recoveryCodes: {
      async replaceForUser(userId, codeHashes) {
        const client = await pool.connect();
        try {
          await client.query('BEGIN');
          await client.query(`DELETE FROM recovery_codes WHERE user_id = $1`, [userId]);
          for (const h of codeHashes) {
            await client.query(`INSERT INTO recovery_codes (user_id, code_hash) VALUES ($1, $2)`, [userId, h]);
          }
          await client.query('COMMIT');
        } catch (e) {
          await client.query('ROLLBACK');
          throw e;
        } finally {
          client.release();
        }
      },
      async consume(userId, codeHash) {
        const res = await pool.query(
          `UPDATE recovery_codes SET used_at = now()
           WHERE user_id = $1 AND code_hash = $2 AND used_at IS NULL`,
          [userId, codeHash],
        );
        return (res.rowCount ?? 0) > 0;
      },
      async countUnused(userId) {
        const { rows } = await pool.query<{ n: string }>(
          `SELECT count(*)::text AS n FROM recovery_codes WHERE user_id = $1 AND used_at IS NULL`,
          [userId],
        );
        return Number(rows[0]!.n);
      },
    },
  };
}
