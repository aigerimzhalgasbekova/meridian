import express, { type Express, type RequestHandler } from 'express';
import QRCode from 'qrcode-svg';
import { randomBytes } from 'node:crypto';
import { withMinDuration, type AppContext } from './context.js';
import { decoyHash, hashPassword, verifyPassword } from './crypto/password.js';
import { hashToken, newToken } from './crypto/tokens.js';
import { base32Decode } from './crypto/base32.js';
import { open, seal } from './crypto/secretbox.js';
import { generateTotpSecret, otpauthUri, verifyTotp } from './crypto/totp.js';
import {
  newCsrfToken,
  newSessionId,
  rateLimit,
  requireAuth,
  requireCsrf,
  requireSession,
  sessionCookie,
  sessionLoader,
} from './http/middleware.js';
import { SEND_EMAIL } from './jobs/handlers.js';
import type { Session, User } from './store/types.js';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MIN_PASSWORD = 8;

function badRequest(res: express.Response, error: string): void {
  res.status(400).json({ error });
}

function isEmail(v: unknown): v is string {
  return typeof v === 'string' && v.length <= 254 && EMAIL_RE.test(v);
}

function isPassword(v: unknown): v is string {
  return typeof v === 'string' && v.length >= MIN_PASSWORD && v.length <= 1024;
}

/** Recovery codes: 10 codes, 10 base32 chars each, shown once, stored hashed. */
function generateRecoveryCodes(): { raw: string[]; hashes: string[] } {
  const raw = Array.from({ length: 10 }, () => {
    const s = randomBytes(8).toString('hex').slice(0, 10);
    return `${s.slice(0, 5)}-${s.slice(5)}`;
  });
  return { raw, hashes: raw.map(hashToken) };
}

function meBody(user: User, session: Session) {
  return {
    user: {
      email: user.email,
      emailVerified: user.emailVerified,
      pendingEmail: user.pendingEmail,
      totpEnabled: user.totpSecret !== null,
    },
    csrfToken: session.csrfToken,
    mfaPending: session.mfaPending,
  };
}

export function createApp(ctx: AppContext): Express {
  const { store, queue, config } = ctx;
  const app = express();
  app.get('/healthz', (_req, res) => {
    res.json({ ok: true });
  });
  app.use(express.json());
  app.use(sessionLoader(ctx));
  const limited = rateLimit(ctx);

  async function startSession(res: express.Response, userId: string, mfaPending: boolean): Promise<Session> {
    const { id, idHash } = newSessionId();
    const now = ctx.now();
    const session: Session = {
      idHash,
      userId,
      csrfToken: newCsrfToken(),
      mfaPending,
      createdAt: now,
      expiresAt: new Date(now.getTime() + config.sessionTtlMs),
    };
    await store.sessions.create(session);
    res.setHeader('Set-Cookie', sessionCookie(id, config.sessionTtlMs, config.secureCookies));
    return session;
  }

  async function sendVerifyEmail(userId: string, address: string): Promise<void> {
    const { token, hash } = newToken();
    await store.tokens.create({
      userId,
      purpose: 'verify_email',
      tokenHash: hash,
      payload: address,
      expiresAt: new Date(ctx.now().getTime() + config.verifyTokenTtlMs),
    });
    await queue.enqueue(SEND_EMAIL, {
      to: address,
      subject: `Verify your ${config.issuer} email address`,
      text: `Confirm this address by opening:\n\n${config.baseUrl}/verify-email?token=${token}\n\nThis link expires in ${Math.round(config.verifyTokenTtlMs / 3_600_000)} hours.`,
    }, { runAt: ctx.now() });
  }

  async function sendResetEmail(userId: string, address: string, subject: string, lead: string): Promise<void> {
    const { token, hash } = newToken();
    await store.tokens.create({
      userId,
      purpose: 'password_reset',
      tokenHash: hash,
      payload: null,
      expiresAt: new Date(ctx.now().getTime() + config.resetTokenTtlMs),
    });
    await queue.enqueue(SEND_EMAIL, {
      to: address,
      subject,
      text: `${lead}\n\n${config.baseUrl}/reset?token=${token}\n\nThis link expires in ${Math.round(config.resetTokenTtlMs / 60_000)} minutes and can be used once.`,
    }, { runAt: ctx.now() });
  }

  const wrap = (fn: RequestHandler): RequestHandler => {
    return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
  };

  // ---- Auth -----------------------------------------------------------------

  app.post('/api/auth/signup', limited, wrap(async (req, res) => {
    const { email, password } = req.body ?? {};
    if (!isEmail(email)) return badRequest(res, 'valid email required');
    if (!isPassword(password)) return badRequest(res, `password must be at least ${MIN_PASSWORD} characters`);
    // Enumeration-safe (mirrors /forgot): identical body + minimum duration
    // whether or not the address is taken. Both branches send mail, so the
    // address owner always has somewhere to go — a taken address gets a reset
    // link rather than the silence the UI's "check your email" would belie.
    await withMinDuration(config.uniformDelayMs, async () => {
      const existing = await store.users.findByEmail(email);
      if (existing) {
        await sendResetEmail(existing.id, existing.email,
          `Someone tried to create a ${config.issuer} account with your email`,
          'You already have an account with this address. If that was you, sign in — or reset your password by opening:');
        return;
      }
      const user = await store.users.create({
        email,
        emailVerified: false,
        pendingEmail: null,
        passwordHash: await hashPassword(password),
        totpSecret: null,
        totpPendingSecret: null,
        totpLastCounter: null,
      });
      await sendVerifyEmail(user.id, email);
    });
    res.status(202).json({ ok: true });
  }));

  app.post('/api/auth/login', limited, wrap(async (req, res) => {
    const { email, password } = req.body ?? {};
    if (typeof email !== 'string' || typeof password !== 'string') return badRequest(res, 'email and password required');
    const user = await store.users.findByEmail(email);
    // Always verify against a real hash so timing does not reveal existence.
    const ok = await verifyPassword(user?.passwordHash ?? (await decoyHash()), password);
    if (!user || !ok) {
      res.status(401).json({ error: 'invalid email or password' });
      return;
    }
    const session = await startSession(res, user.id, user.totpSecret !== null);
    res.json(meBody(user, session));
  }));

  // TOTP step-up: 6-digit code or a recovery code completes the MFA-pending session.
  app.post('/api/auth/totp', limited, requireSession, requireCsrf, wrap(async (req, res) => {
    const session = req.session!;
    const user = req.user!;
    const { code } = req.body ?? {};
    if (typeof code !== 'string' || !user.totpSecret) return badRequest(res, 'code required');

    if (/^\d{6}$/.test(code)) {
      const secret = base32Decode(open(user.totpSecret, config.totpKek));
      const counter = verifyTotp(secret, code, ctx.now().getTime() / 1000);
      // Replay defense is atomic: advanceTotpCounter rejects (0 rows) any counter
      // at or before the last accepted one, so concurrent replays can't both pass.
      if (counter === null || !(await store.users.advanceTotpCounter(user.id, counter.toString()))) {
        res.status(401).json({ error: 'invalid code' });
        return;
      }
    } else {
      const consumed = await store.recoveryCodes.consume(user.id, hashToken(code.trim().toLowerCase()));
      if (!consumed) {
        res.status(401).json({ error: 'invalid code' });
        return;
      }
    }
    await store.sessions.update(session.idHash, { mfaPending: false });
    res.json(meBody(user, { ...session, mfaPending: false }));
  }));

  app.post('/api/auth/logout', requireSession, requireCsrf, wrap(async (req, res) => {
    await store.sessions.delete(req.session!.idHash);
    res.setHeader('Set-Cookie', sessionCookie('', 0, config.secureCookies));
    res.json({ ok: true });
  }));

  app.get('/api/me', requireSession, (req, res) => {
    res.json(meBody(req.user!, req.session!));
  });

  // ---- Password reset (enumeration-safe) -------------------------------------

  app.post('/api/auth/forgot', limited, wrap(async (req, res) => {
    const { email } = req.body ?? {};
    if (!isEmail(email)) return badRequest(res, 'valid email required');
    // Identical body + minimum duration whether or not the account exists.
    await withMinDuration(config.uniformDelayMs, async () => {
      const user = await store.users.findByEmail(email);
      if (!user) return;
      await sendResetEmail(user.id, user.email,
        `Reset your ${config.issuer} password`,
        'Reset your password by opening:');
    });
    res.status(202).json({ ok: true });
  }));

  app.post('/api/auth/reset', limited, wrap(async (req, res) => {
    const { token, password } = req.body ?? {};
    if (typeof token !== 'string' || token.length === 0) return badRequest(res, 'token required');
    if (!isPassword(password)) return badRequest(res, `password must be at least ${MIN_PASSWORD} characters`);
    const record = await store.tokens.findActiveByHash(hashToken(token), 'password_reset', ctx.now());
    // markUsed is atomic: a concurrent double-submit loses here (single use).
    if (!record || !(await store.tokens.markUsed(record.id, ctx.now()))) {
      res.status(400).json({ error: 'invalid or expired token' });
      return;
    }
    await store.tokens.revokeAllForUser(record.userId, 'password_reset');
    await store.users.update(record.userId, { passwordHash: await hashPassword(password) });
    await store.sessions.deleteAllForUser(record.userId);
    res.json({ ok: true });
  }));

  // ---- Email verification -----------------------------------------------------

  app.post('/api/auth/verify-email', limited, wrap(async (req, res) => {
    const { token } = req.body ?? {};
    if (typeof token !== 'string' || token.length === 0) return badRequest(res, 'token required');
    const record = await store.tokens.findActiveByHash(hashToken(token), 'verify_email', ctx.now());
    if (!record || !(await store.tokens.markUsed(record.id, ctx.now()))) {
      res.status(400).json({ error: 'invalid or expired token' });
      return;
    }
    const user = await store.users.findById(record.userId);
    const address = record.payload;
    if (!user || !address) {
      res.status(400).json({ error: 'invalid or expired token' });
      return;
    }
    if (address === user.email) {
      await store.users.update(user.id, { emailVerified: true });
    } else if (address === user.pendingEmail) {
      // Email change confirmed: only now does the old address stop being the login.
      if (await store.users.findByEmail(address)) {
        res.status(409).json({ error: 'that email is already in use' });
        return;
      }
      await store.users.update(user.id, { email: address, pendingEmail: null, emailVerified: true });
    } else {
      // Token for an address that is no longer pending (superseded change).
      res.status(400).json({ error: 'invalid or expired token' });
      return;
    }
    res.json({ ok: true, email: address });
  }));

  // ---- Account ----------------------------------------------------------------

  app.post('/api/account/email', requireAuth, requireCsrf, wrap(async (req, res) => {
    const user = req.user!;
    const { email } = req.body ?? {};
    if (!isEmail(email)) return badRequest(res, 'valid email required');
    if (email === user.email) return badRequest(res, 'that is already your email');
    if (await store.users.findByEmail(email)) {
      res.status(409).json({ error: 'that email is already in use' });
      return;
    }
    // Old address stays active until the new one is confirmed.
    await store.tokens.revokeAllForUser(user.id, 'verify_email');
    await store.users.update(user.id, { pendingEmail: email });
    await sendVerifyEmail(user.id, email);
    res.status(202).json({ ok: true, pendingEmail: email });
  }));

  // ---- Security: TOTP enrollment ------------------------------------------------

  app.post('/api/security/totp/setup', requireAuth, requireCsrf, wrap(async (req, res) => {
    const user = req.user!;
    if (user.totpSecret) {
      res.status(409).json({ error: 'TOTP is already enabled' });
      return;
    }
    const { base32 } = generateTotpSecret();
    // Encrypted at rest like totpSecret: it lives across the setup->activate hop.
    await store.users.update(user.id, { totpPendingSecret: seal(base32, config.totpKek) });
    const uri = otpauthUri(base32, user.email, config.issuer);
    const qrSvg = new QRCode({ content: uri, padding: 2, width: 200, height: 200, ecl: 'M', join: true }).svg();
    res.json({ secret: base32, otpauthUri: uri, qrSvg });
  }));

  app.post('/api/security/totp/activate', requireAuth, requireCsrf, wrap(async (req, res) => {
    const user = req.user!;
    const { code } = req.body ?? {};
    if (!user.totpPendingSecret) return badRequest(res, 'no enrollment in progress');
    if (typeof code !== 'string') return badRequest(res, 'code required');
    const pendingBase32 = open(user.totpPendingSecret, config.totpKek);
    const counter = verifyTotp(base32Decode(pendingBase32), code, ctx.now().getTime() / 1000);
    if (counter === null) {
      res.status(401).json({ error: 'invalid code' });
      return;
    }
    const { raw, hashes } = generateRecoveryCodes();
    await store.recoveryCodes.replaceForUser(user.id, hashes);
    await store.users.update(user.id, {
      // Encrypted at rest (recoverable, so cannot be hashed).
      totpSecret: seal(pendingBase32, config.totpKek),
      totpPendingSecret: null,
      totpLastCounter: counter.toString(),
    });
    // Recovery codes are returned exactly once; only hashes are stored.
    res.json({ ok: true, recoveryCodes: raw });
  }));

  // ---- Security: sessions --------------------------------------------------------

  app.get('/api/security/sessions', requireAuth, wrap(async (req, res) => {
    const sessions = await store.sessions.listForUser(req.user!.id);
    res.json({
      sessions: sessions.map((s) => ({
        id: s.idHash, // already a SHA-256 hash, safe to expose as an identifier
        createdAt: s.createdAt,
        expiresAt: s.expiresAt,
        current: s.idHash === req.session!.idHash,
      })),
    });
  }));

  app.delete('/api/security/sessions/:id', requireAuth, requireCsrf, wrap(async (req, res) => {
    const sessions = await store.sessions.listForUser(req.user!.id);
    const target = sessions.find((s) => s.idHash === req.params.id);
    if (!target) {
      res.status(404).json({ error: 'session not found' });
      return;
    }
    await store.sessions.delete(target.idHash);
    res.json({ ok: true });
  }));

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
    console.error(err);
    res.status(500).json({ error: 'internal error' });
  });

  return app;
}
