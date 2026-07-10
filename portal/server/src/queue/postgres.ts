import type { Pool } from 'pg';
import { DEFAULT_MAX_ATTEMPTS, type Job, type JobQueue, type JobStatus } from './types.js';

interface JobRow {
  id: string;
  type: string;
  payload: Record<string, unknown>;
  status: JobStatus;
  attempts: number;
  max_attempts: number;
  run_at: Date;
  last_error: string | null;
  created_at: Date;
}

function toJob(r: JobRow): Job {
  return {
    id: r.id,
    type: r.type,
    payload: r.payload,
    status: r.status,
    attempts: r.attempts,
    maxAttempts: r.max_attempts,
    runAt: r.run_at,
    lastError: r.last_error,
    createdAt: r.created_at,
  };
}

export function postgresQueue(pool: Pool): JobQueue {
  return {
    async enqueue(type, payload, opts = {}) {
      const { rows } = await pool.query<JobRow>(
        `INSERT INTO jobs (type, payload, max_attempts, run_at)
         VALUES ($1, $2, $3, $4) RETURNING *`,
        [type, JSON.stringify(payload), opts.maxAttempts ?? DEFAULT_MAX_ATTEMPTS, opts.runAt ?? new Date()],
      );
      return toJob(rows[0]!);
    },

    async claim(now) {
      // The showcase query: SKIP LOCKED means concurrent workers each grab a
      // different row, no advisory locks, no polling contention.
      const { rows } = await pool.query<JobRow>(
        `UPDATE jobs SET status = 'running', attempts = attempts + 1
         WHERE id = (
           SELECT id FROM jobs
           WHERE status = 'pending' AND run_at <= $1
           ORDER BY run_at, created_at
           FOR UPDATE SKIP LOCKED
           LIMIT 1
         )
         RETURNING *`,
        [now],
      );
      return rows[0] ? toJob(rows[0]) : null;
    },

    async complete(id) {
      await pool.query(`UPDATE jobs SET status = 'done' WHERE id = $1`, [id]);
    },

    async fail(id, error, now) {
      // attempts was already incremented at claim time. Backoff mirrors
      // backoffMs(): 1s * 4^(attempts-1), capped at 300s.
      await pool.query(
        `UPDATE jobs SET
           last_error = $2,
           status = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'pending' END,
           run_at = CASE WHEN attempts >= max_attempts THEN run_at
                    ELSE $3::timestamptz + make_interval(secs => LEAST(power(4, attempts - 1), 300)) END
         WHERE id = $1`,
        [id, error, now],
      );
    },

    async get(id) {
      const { rows } = await pool.query<JobRow>(`SELECT * FROM jobs WHERE id = $1`, [id]);
      return rows[0] ? toJob(rows[0]) : null;
    },

    async listByStatus(status) {
      const { rows } = await pool.query<JobRow>(`SELECT * FROM jobs WHERE status = $1 ORDER BY created_at`, [status]);
      return rows.map(toJob);
    },

    async recover() {
      // ponytail: startup requeue of orphaned 'running' jobs. Fine for the
      // single-worker deploy here; a multi-worker fleet would also reset peers'
      // in-flight jobs (handlers are idempotent, so it's safe but wasteful) —
      // upgrade path is a claimed_at column + stale-timeout reaper in claim().
      const res = await pool.query(`UPDATE jobs SET status = 'pending' WHERE status = 'running'`);
      return res.rowCount ?? 0;
    },
  };
}
