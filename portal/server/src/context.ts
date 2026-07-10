import type { Store } from './store/types.js';
import type { JobQueue } from './queue/types.js';

export interface Config {
  /** Absolute URL links in emails point at (the web app). */
  baseUrl: string;
  issuer: string;
  sessionTtlMs: number;
  resetTokenTtlMs: number;
  verifyTokenTtlMs: number;
  /** Minimum duration for enumeration-sensitive endpoints (uniform timing). */
  uniformDelayMs: number;
  rateLimit: { limit: number; windowMs: number };
  secureCookies: boolean;
  /** 32-byte key-encryption key for at-rest secrets (TOTP). From env in prod. */
  totpKek: Buffer;
}

export const defaultConfig: Config = {
  baseUrl: 'http://localhost:5173',
  issuer: 'Meridian',
  sessionTtlMs: 24 * 60 * 60 * 1000,
  resetTokenTtlMs: 15 * 60 * 1000,
  verifyTokenTtlMs: 24 * 60 * 60 * 1000,
  uniformDelayMs: 100,
  rateLimit: { limit: 10, windowMs: 60_000 },
  // Secure-by-default: an unset/misspelled NODE_ENV must not silently ship
  // insecure cookies. Local dev opts out explicitly (see index.ts).
  secureCookies: true,
  // ponytail: obvious non-secret placeholder for dev/test; prod must set
  // PORTAL_TOTP_KEK (index.ts refuses the DB path without it).
  totpKek: Buffer.alloc(32, 7),
};

export interface AppContext {
  store: Store;
  queue: JobQueue;
  config: Config;
  /** Injectable clock so tests control expiry and backoff. */
  now: () => Date;
}

/**
 * Enumeration defense: run `fn`, but never respond faster than `ms`.
 * Combined with identical response bodies, the account-exists and
 * account-missing paths are indistinguishable to a caller.
 */
export async function withMinDuration<T>(ms: number, fn: () => Promise<T>): Promise<T> {
  const start = Date.now();
  const result = await fn();
  const remaining = ms - (Date.now() - start);
  if (remaining > 0) await new Promise((r) => setTimeout(r, remaining));
  return result;
}
