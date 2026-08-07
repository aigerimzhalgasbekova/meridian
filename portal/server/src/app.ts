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
  return typeof v === 'string' && v.length <= 254 && EMAIL_RE.test(v.trim());
}

/**
 * The canonical form an address is stored and looked up by. `users.email` is a
 * plain case-sensitive UNIQUE column, so without this `Alice@Example.com` and
 * `alice@example.com` are two accounts no login can tell apart — and the
 * enumeration-safe /forgot path would silently send nothing to the one you
 * cannot reach. Every request-supplied address goes through here.
 */
function normalizeEmail(v: string): string {
  return v.trim().toLowerCase();
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

export function createApp(ctx: AppContext): Express {
  const { store, queue, config } = ctx;

  async function meBody(user: User, session: Session) {
    return {
      user: {
        email: user.email,
        emailVerified: user.emailVerified,
        pendingEmail: user.pendingEmail,
        totpEnabled: user.totpSecret !== null,
        // Without this the last recovery code is spent silently and the account
        // is only discovered to be unrecoverable at the moment it matters.
        recoveryCodesRemaining: user.totpSecret ? await store.recoveryCodes.countUnused(user.id) : 0,
      },
      csrfToken: session.csrfToken,
      mfaPending: session.mfaPending,
    };
  }

  const app = express();
  // Trust exactly one hop, so `req.ip` is the address the load balancer
  // observed rather than the balancer itself — otherwise the rate limiter
  // buckets the whole internet together. Everything left of that last hop
  // is client-supplied and stays untrusted.
  if (config.trustProxy) app.set('trust proxy', 1);
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

  /**
   * Sent the moment a second factor is activated. Password re-auth on /setup
   * only stops an attacker who stole the cookie alone; one who phished or
   * stuffed the *password* passes it, enrolls their own authenticator, and the
   * owner's own remedy (reset the password, log in) then lands on an
   * mfaPending session — which requireAuth rejects, so /totp/disable is out of
   * reach and the account is gone. This link is the escape: it lives in the
   * inbox, and an inbox-only attacker gains nothing from it (revoking a factor
   * is never satisfying one).
   */
  async function sendUndoTotpEmail(userId: string, address: string): Promise<void> {
    const { token, hash } = newToken();
    await store.tokens.create({
      userId,
      purpose: 'undo_totp',
      tokenHash: hash,
      payload: null,
      // ponytail: reuses the verify-email TTL (24h) rather than adding a knob.
      expiresAt: new Date(ctx.now().getTime() + config.verifyTokenTtlMs),
    });
    await queue.enqueue(SEND_EMAIL, {
      to: address,
      subject: `Two-factor authentication was enabled on your ${config.issuer} account`,
      text: `If this was you, nothing to do — keep your recovery codes safe.\n\nIf it was not, turn the second factor off and then change your password:\n\n${config.baseUrl}/undo-totp?token=${token}\n\nThis link expires in ${Math.round(config.verifyTokenTtlMs / 3_600_000)} hours and can be used once.`,
    }, { runAt: ctx.now() });
  }

  /**
   * Mailed to the address a confirmed change moves *away from*. The login
   * address is the root of every email-based recovery path we have — including
   * the undo_totp notice above — so an attacker who relocates it first receives
   * every later warning himself and the owner's /forgot goes to an address on
   * no account. This is the counterweight: it lands in the old inbox and its
   * token puts the account back.
   */
  async function sendEmailChangedNotice(userId: string, oldAddress: string, newAddress: string): Promise<void> {
    const { token, hash } = newToken();
    await store.tokens.create({
      userId,
      purpose: 'undo_email',
      tokenHash: hash,
      payload: oldAddress,
      // ponytail: reuses the verify-email TTL (24h) rather than adding a knob.
      expiresAt: new Date(ctx.now().getTime() + config.verifyTokenTtlMs),
    });
    await queue.enqueue(SEND_EMAIL, {
      to: oldAddress,
      subject: `The sign-in address on your ${config.issuer} account was changed`,
      text: `This account now signs in as ${newAddress}.\n\nIf that was not you, put it back — this also signs every session out and removes any authenticator app added since the change:\n\n${config.baseUrl}/undo-email?token=${token}\n\nThis link expires in ${Math.round(config.verifyTokenTtlMs / 3_600_000)} hours and can be used once.`,
    }, { runAt: ctx.now() });
  }

  const wrap = (fn: RequestHandler): RequestHandler => {
    return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
  };

  // ---- Auth -----------------------------------------------------------------

  app.post('/api/auth/signup', limited, wrap(async (req, res) => {
    const { email: rawEmail, password } = req.body ?? {};
    if (!isEmail(rawEmail)) return badRequest(res, 'valid email required');
    if (!isPassword(password)) return badRequest(res, `password must be at least ${MIN_PASSWORD} characters`);
    const email = normalizeEmail(rawEmail);
    // Enumeration-safe (mirrors /forgot): identical body + minimum duration
    // whether or not the address is taken. Both branches send mail, so the
    // address owner always has somewhere to go — a taken address gets a reset
    // link rather than the silence the UI's "check your email" would belie.
    await withMinDuration(config.uniformDelayMs, async () => {
      const existing = await store.users.findByEmail(email);
      if (existing) {
        // withMinDuration is a floor, not a budget: the new-account branch pays
        // an Argon2id hash and this one would not, so under CPU pressure the
        // hash outruns the floor and the two branches separate. Pay it on both.
        // (Not decoyHash(): that memoises and costs nothing after the first call.)
        await hashPassword(password);
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
    const { email: rawEmail, password } = req.body ?? {};
    if (typeof rawEmail !== 'string' || typeof password !== 'string') return badRequest(res, 'email and password required');
    const user = await store.users.findByEmail(normalizeEmail(rawEmail));
    // Always verify against a real hash so timing does not reveal existence.
    const ok = await verifyPassword(user?.passwordHash ?? (await decoyHash()), password);
    if (!user || !ok) {
      res.status(401).json({ error: 'invalid email or password' });
      return;
    }
    const session = await startSession(res, user.id, user.totpSecret !== null);
    res.json(await meBody(user, session));
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
    res.json(await meBody(user, { ...session, mfaPending: false }));
  }));

  app.post('/api/auth/logout', requireSession, requireCsrf, wrap(async (req, res) => {
    await store.sessions.delete(req.session!.idHash);
    res.setHeader('Set-Cookie', sessionCookie('', 0, config.secureCookies));
    res.json({ ok: true });
  }));

  app.get('/api/me', requireSession, wrap(async (req, res) => {
    res.json(await meBody(req.user!, req.session!));
  }));

  // ---- Password reset (enumeration-safe) -------------------------------------

  app.post('/api/auth/forgot', limited, wrap(async (req, res) => {
    const { email: rawEmail } = req.body ?? {};
    if (!isEmail(rawEmail)) return badRequest(res, 'valid email required');
    // Identical body + minimum duration whether or not the account exists.
    await withMinDuration(config.uniformDelayMs, async () => {
      const user = await store.users.findByEmail(normalizeEmail(rawEmail));
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
    // A reset is the documented remedy for a compromised account, so it must
    // also kill the capabilities an attacker extracted while holding a session.
    // A queued email change is one: verify-email needs no session, so an
    // outstanding change token would still flip the login address to theirs
    // (24h TTL) long after the reset destroyed their session. Clearing
    // pendingEmail is what cancels it — /verify-email rejects a payload that
    // matches neither users.email nor pendingEmail. Revoking the whole
    // verify_email purpose here instead would also burn the signup token, and
    // there is no resend route, so an unverified account could never verify.
    await store.users.update(record.userId, { passwordHash: await hashPassword(password), pendingEmail: null });
    await store.sessions.deleteAllForUser(record.userId);
    res.json({ ok: true });
  }));

  // ---- Email verification -----------------------------------------------------

  app.post('/api/auth/verify-email', limited, wrap(async (req, res) => {
    const { token } = req.body ?? {};
    if (typeof token !== 'string' || token.length === 0) return badRequest(res, 'token required');
    const record = await store.tokens.findActiveByHash(hashToken(token), 'verify_email', ctx.now());
    const user = record ? await store.users.findById(record.userId) : null;
    const address = record?.payload;
    // Token for an address that is no longer pending (superseded change) is
    // genuinely invalid; burning it below is the point.
    if (!record || !user || !address || (address !== user.email && address !== user.pendingEmail)) {
      res.status(400).json({ error: 'invalid or expired token' });
      return;
    }
    // Someone else registered the address during the 24h window: a recoverable
    // conflict, not an attack, so check it *before* spending the single-use
    // token — otherwise the user's only route out is to restart the change.
    if (address === user.pendingEmail && (await store.users.findByEmail(address))) {
      res.status(409).json({ error: 'that email is already in use' });
      return;
    }
    // markUsed is atomic: a concurrent double-submit loses here (single use).
    if (!(await store.tokens.markUsed(record.id, ctx.now()))) {
      res.status(400).json({ error: 'invalid or expired token' });
      return;
    }
    if (address === user.email) {
      await store.users.update(user.id, { emailVerified: true });
    } else {
      // Email change confirmed: only now does the old address stop being the login.
      const previous = user.email; // read before the update, not after
      await store.users.update(user.id, { email: address, pendingEmail: null, emailVerified: true });
      await sendEmailChangedNotice(user.id, previous, address);
    }
    res.json({ ok: true, email: address });
  }));

  /**
   * The old inbox's counterweight to a confirmed address change. Authorized by
   * the mailed token alone, like /reset and /verify-email: by the time it is
   * needed the account no longer answers to the address its owner has.
   */
  app.post('/api/auth/undo-email', limited, wrap(async (req, res) => {
    const { token } = req.body ?? {};
    if (typeof token !== 'string' || token.length === 0) return badRequest(res, 'token required');
    const record = await store.tokens.findActiveByHash(hashToken(token), 'undo_email', ctx.now());
    const previous = record?.payload;
    if (!record || !previous) {
      res.status(400).json({ error: 'invalid or expired token' });
      return;
    }
    // Someone else registered the old address in the meantime: a recoverable
    // conflict, so check it before spending the token (mirrors /verify-email).
    const holder = await store.users.findByEmail(previous);
    if (holder && holder.id !== record.userId) {
      res.status(409).json({ error: 'that email is already in use' });
      return;
    }
    // markUsed is atomic: a concurrent double-submit loses here (single use).
    if (!(await store.tokens.markUsed(record.id, ctx.now()))) {
      res.status(400).json({ error: 'invalid or expired token' });
      return;
    }
    await store.users.update(record.userId, {
      email: previous,
      // Clicking a link mailed here is proof of receipt, and pendingEmail: null
      // cancels any further change the mover had queued.
      emailVerified: true,
      pendingEmail: null,
      // Whoever moved the address had the password, so a factor enrolled after
      // the move is theirs — and its own undo notice went to the address they
      // moved to. Not a new bypass: undo_totp already lets the account inbox
      // clear a factor, and this needs that inbox *plus* a change only the
      // password could have started.
      totpSecret: null,
      totpPendingSecret: null,
      totpLastCounter: null,
    });
    await store.recoveryCodes.replaceForUser(record.userId, []);
    await store.sessions.deleteAllForUser(record.userId);
    // ponytail: siblings from a *chain* of changes (A->B->C) are deliberately
    // left live — revoking them would let the mover burn the owner's token by
    // moving twice. So a chain still ends with whoever redeems last. Closing it
    // needs tokens ordered by created_at (revoke only those minted after this
    // one), i.e. a new TokenRepo method; out of proportion until it is seen.
    res.json({ ok: true, email: previous });
  }));

  // ---- Account ----------------------------------------------------------------

  // `limited` matters here as much as on /api/auth/*: the 409 below is a
  // clean account-existence oracle, and one throwaway account buys unlimited
  // probes without it.
  app.post('/api/account/email', limited, requireAuth, requireCsrf, wrap(async (req, res) => {
    const user = req.user!;
    const { email: rawEmail } = req.body ?? {};
    if (!isEmail(rawEmail)) return badRequest(res, 'valid email required');
    // Moving the login address is a credential change, not a profile edit: it
    // is the root of /forgot and of every mailed notice, so without the
    // password a stolen cookie relocates it and then simply asks for a reset.
    if (!(await reauthenticated(req, res))) return;
    const email = normalizeEmail(rawEmail);
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

  /**
   * Re-authenticate with the account password before changing the second
   * factor or the login address. A session cookie alone is not enough: a hijacked 24h session
   * could otherwise enroll the attacker's authenticator on an account with no
   * MFA, and /api/auth/reset deliberately does not clear TOTP — so the owner
   * would be locked out permanently with no route back.
   */
  async function reauthenticated(req: express.Request, res: express.Response): Promise<boolean> {
    const { password } = req.body ?? {};
    if (typeof password !== 'string' || !(await verifyPassword(req.user!.passwordHash, password))) {
      res.status(401).json({ error: 'password required' });
      return false;
    }
    return true;
  }

  app.post('/api/security/totp/setup', limited, requireAuth, requireCsrf, wrap(async (req, res) => {
    const user = req.user!;
    if (!(await reauthenticated(req, res))) return;
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

  // No password re-auth here: the pending secret can only have been created by
  // /setup, which already required it, and activating it only ever enables the
  // authenticator the caller of /setup scanned.
  app.post('/api/security/totp/activate', limited, requireAuth, requireCsrf, wrap(async (req, res) => {
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
    // Only the newest undo link stays live.
    await store.tokens.revokeAllForUser(user.id, 'undo_totp');
    await sendUndoTotpEmail(user.id, user.email);
    // Recovery codes are returned exactly once; only hashes are stored.
    res.json({ ok: true, recoveryCodes: raw });
  }));

  // The inbox-side counterpart to /totp/disable, authorized by the mailed token
  // alone (like /reset and /verify-email) because the owner reaching for it is
  // by definition locked out of the session that /disable requires.
  app.post('/api/auth/undo-totp', limited, wrap(async (req, res) => {
    const { token } = req.body ?? {};
    if (typeof token !== 'string' || token.length === 0) return badRequest(res, 'token required');
    const record = await store.tokens.findActiveByHash(hashToken(token), 'undo_totp', ctx.now());
    // markUsed is atomic: a concurrent double-submit loses here (single use).
    if (!record || !(await store.tokens.markUsed(record.id, ctx.now()))) {
      res.status(400).json({ error: 'invalid or expired token' });
      return;
    }
    await store.users.update(record.userId, { totpSecret: null, totpPendingSecret: null, totpLastCounter: null });
    await store.recoveryCodes.replaceForUser(record.userId, []);
    // The enrolling session is the one being undone, so it must not survive —
    // and every other session was stepped up against a factor that no longer
    // exists. The owner logs back in with the password and resets it from there.
    await store.sessions.deleteAllForUser(record.userId);
    res.json({ ok: true });
  }));

  // The way out. Without it enrollment is a one-way door: a lost authenticator
  // plus ten spent recovery codes is an account no one can reach, and reset
  // deliberately does not clear TOTP. Requires a *fully* authenticated session
  // (the step-up already passed) plus the password, so it is not an MFA bypass.
  app.post('/api/security/totp/disable', limited, requireAuth, requireCsrf, wrap(async (req, res) => {
    const user = req.user!;
    if (!(await reauthenticated(req, res))) return;
    await store.users.update(user.id, { totpSecret: null, totpPendingSecret: null, totpLastCounter: null });
    await store.recoveryCodes.replaceForUser(user.id, []);
    // Nothing left to undo, so the mailed undo link stops being a live way to
    // sign every session out.
    await store.tokens.revokeAllForUser(user.id, 'undo_totp');
    res.json({ ok: true });
  }));

  app.post('/api/security/totp/recovery-codes', limited, requireAuth, requireCsrf, wrap(async (req, res) => {
    const user = req.user!;
    if (!(await reauthenticated(req, res))) return;
    if (!user.totpSecret) return badRequest(res, 'TOTP is not enabled');
    const { raw, hashes } = generateRecoveryCodes();
    // Replaces every old code, used or not: a regenerate must not leave a
    // previously-issued code live.
    await store.recoveryCodes.replaceForUser(user.id, hashes);
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
