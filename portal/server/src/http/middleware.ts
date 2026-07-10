import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import type { NextFunction, Request, RequestHandler, Response } from 'express';
import type { AppContext } from '../context.js';
import type { Session, User } from '../store/types.js';

export const SESSION_COOKIE = 'portal_session';

declare module 'express-serve-static-core' {
  interface Request {
    session?: Session;
    user?: User;
  }
}

export function hashSessionId(id: string): string {
  return createHash('sha256').update(id).digest('hex');
}

// ponytail: hand-rolled cookie parse/serialize — two functions beat a dependency.
export function parseCookies(header: string | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1) continue;
    out[part.slice(0, eq).trim()] = decodeURIComponent(part.slice(eq + 1).trim());
  }
  return out;
}

export function sessionCookie(value: string, maxAgeMs: number, secure: boolean): string {
  const attrs = [
    `${SESSION_COOKIE}=${value}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${Math.floor(maxAgeMs / 1000)}`,
  ];
  if (secure) attrs.push('Secure');
  return attrs.join('; ');
}

/** Loads (and expires) the session from the cookie; attaches req.session/req.user. */
export function sessionLoader(ctx: AppContext): RequestHandler {
  return async (req, _res, next) => {
    try {
      const raw = parseCookies(req.headers.cookie)[SESSION_COOKIE];
      if (!raw) return next();
      const session = await ctx.store.sessions.findByIdHash(hashSessionId(raw));
      if (!session) return next();
      if (session.expiresAt <= ctx.now()) {
        await ctx.store.sessions.delete(session.idHash);
        return next();
      }
      req.session = session;
      const user = await ctx.store.users.findById(session.userId);
      if (user) req.user = user;
      next();
    } catch (err) {
      next(err);
    }
  };
}

/** Fully authenticated: session exists and the TOTP step-up (if any) is done. */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  if (!req.session || !req.user || req.session.mfaPending) {
    res.status(401).json({ error: 'authentication required' });
    return;
  }
  next();
}

/** Session exists but may still be awaiting the TOTP step (login second factor). */
export function requireSession(req: Request, res: Response, next: NextFunction): void {
  if (!req.session || !req.user) {
    res.status(401).json({ error: 'authentication required' });
    return;
  }
  next();
}

/** Double-submit CSRF: mutations must echo the session's token in a header. */
export function requireCsrf(req: Request, res: Response, next: NextFunction): void {
  const presented = req.headers['x-csrf-token'];
  const expected = req.session?.csrfToken;
  if (
    typeof presented !== 'string' ||
    !expected ||
    presented.length !== expected.length ||
    !timingSafeEqual(Buffer.from(presented), Buffer.from(expected))
  ) {
    res.status(403).json({ error: 'invalid CSRF token' });
    return;
  }
  next();
}

export function newSessionId(): { id: string; idHash: string } {
  const id = randomBytes(32).toString('base64url');
  return { id, idHash: hashSessionId(id) };
}

export function newCsrfToken(): string {
  return randomBytes(32).toString('base64url');
}

/**
 * Fixed-window in-memory rate limiter for auth endpoints.
 * ponytail: per-process only — the platform seam for distributed limiting is
 * sentinel's decision API; swap this middleware for a sentinel client there.
 */
export function rateLimit(ctx: AppContext): RequestHandler {
  const windows = new Map<string, { count: number; resetAt: number }>();
  return (req, res, next) => {
    const { limit, windowMs } = ctx.config.rateLimit;
    const key = `${req.ip}:${req.path}`;
    const now = ctx.now().getTime();
    let w = windows.get(key);
    if (!w || w.resetAt <= now) {
      w = { count: 0, resetAt: now + windowMs };
      windows.set(key, w);
    }
    if (++w.count > limit) {
      res.status(429).json({ error: 'too many requests' });
      return;
    }
    next();
  };
}
