import { describe, it, expect } from 'vitest';
import { rateLimit } from '../src/http/middleware.js';
import type { AppContext } from '../src/context.js';

/** Minimal context: the limiter reads only config.rateLimit and now(). */
function limiter(windowMs: number, limit: number, now: () => Date) {
  return rateLimit({ config: { rateLimit: { limit, windowMs } }, now } as unknown as AppContext);
}

/** Drives the middleware with a synthetic request; returns the status, or 0 for next(). */
function hit(mw: ReturnType<typeof limiter>, ip: string, path = '/api/auth/login'): number {
  let status = 0;
  const res = { status(c: number) { status = c; return this; }, json() { return this; } };
  mw({ ip, path } as never, res as never, () => {});
  return status;
}

describe('rateLimit', () => {
  it('counts per key and resets on the next window', () => {
    let now = new Date('2026-07-09T12:00:00Z');
    const mw = limiter(60_000, 2, () => now);
    expect(hit(mw, 'a')).toBe(0);
    expect(hit(mw, 'a')).toBe(0);
    expect(hit(mw, 'a')).toBe(429);
    expect(hit(mw, 'b')).toBe(0); // a different source is unaffected
    now = new Date(now.getTime() + 60_001);
    expect(hit(mw, 'a')).toBe(0);
  });

  it('stays linear as fresh keys arrive', () => {
    // The keys are attacker-chosen — one per source address — so the eviction
    // sweep must run at most once per window, not once per new key. Sweeping
    // per key is O(n^2), which on a single-threaded runtime wedges the whole
    // process: 40k keys took 8.3s before this was fixed, ~16ms after.
    const now = new Date('2026-07-09T12:00:00Z');
    const mw = limiter(60_000, 100, () => now);
    const started = Date.now();
    for (let i = 0; i < 40_000; i++) hit(mw, `10.0.${(i >> 8) & 255}.${i & 255}:${i}`);
    expect(Date.now() - started).toBeLessThan(3_000);
  });
});
