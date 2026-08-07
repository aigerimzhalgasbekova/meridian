import type { Pool } from 'pg';
import { DEFAULT_MAX_ATTEMPTS, STALE_CLAIM_ERROR, STALE_CLAIM_MS, type Job, type JobQueue, type JobStatus } from './types.js';

interface JobRow {
  id: string;
  type: string;
  payload: Record<string, unknown>;
  status: JobStatus;
  attempts: number;
  max_attempts: number;
  run_at: Date;
  claimed_at: Date | null;
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
    claimedAt: r.claimed_at,
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
      const staleBefore = new Date(now.getTime() - STALE_CLAIM_MS);
      // The showcase query: SKIP LOCKED means concurrent workers each grab a
      // different row, no advisory locks, no polling contention. The second
      // branch is the crash/blip reaper — a claim older than STALE_CLAIM_MS is
      // up for grabs again. COALESCE covers rows claimed before claimed_at
      // existed, so an in-flight upgrade doesn't strand them.
      const { rows } = await pool.query<JobRow>(
        `UPDATE jobs SET status = 'running', attempts = attempts + 1, claimed_at = $1
         WHERE id = (
           SELECT id FROM jobs
           WHERE (status = 'pending' AND run_at <= $1)
              OR (status = 'running' AND COALESCE(claimed_at, run_at) < $2 AND attempts < max_attempts)
           ORDER BY run_at, created_at
           FOR UPDATE SKIP LOCKED
           LIMIT 1
         )
         RETURNING *`,
        [now, staleBefore],
      );
      if (rows[0]) return toJob(rows[0]);
      // A stale claim still spends an attempt, so a handler that always outlives
      // the window (or a worker that crash-loops on a poison payload) would be
      // redelivered every 5 minutes forever. Park it in the dead-letter state
      // the same way fail() would. Only on an idle poll: the predicate is not
      // sargable against jobs_claim_idx, and running it ahead of every claim
      // put a scan of every pending+running row on the hot path — N+1 of them
      // per tick() drain. Nothing claims these rows in the meantime (the claim
      // above excludes attempts >= max_attempts), so the only cost of waiting
      // for a quiet poll is when the row gets its 'dead' label.
      await pool.query(
        `UPDATE jobs SET status = 'dead', last_error = $2
         WHERE status = 'running' AND COALESCE(claimed_at, run_at) < $1 AND attempts >= max_attempts`,
        [staleBefore, STALE_CLAIM_ERROR],
      );
      return null;
    },

    // claimed_at is the ownership check: `status = 'running'` alone only catches
    // an already-terminal job, so a straggler answering after the reaper handed
    // the job to a peer would still land on the peer's live run.
    async complete(id, claimedAt) {
      await pool.query(`UPDATE jobs SET status = 'done' WHERE id = $1 AND status = 'running' AND claimed_at = $2`, [
        id,
        claimedAt,
      ]);
    },

    async fail(id, error, now, claimedAt) {
      // attempts was already incremented at claim time. Backoff mirrors
      // backoffMs(): 1s * 4^(attempts-1), capped at 300s.
      await pool.query(
        `UPDATE jobs SET
           last_error = $2,
           status = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'pending' END,
           run_at = CASE WHEN attempts >= max_attempts THEN run_at
                    ELSE $3::timestamptz + make_interval(secs => LEAST(power(4, attempts - 1), 300)) END
         WHERE id = $1 AND status = 'running' AND claimed_at = $4`,
        [id, error, now, claimedAt],
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
  };
}
