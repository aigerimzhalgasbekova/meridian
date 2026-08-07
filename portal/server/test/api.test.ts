import { describe, expect, it } from 'vitest';
import request from 'supertest';
import { totp } from '../src/crypto/totp.js';
import { base32Decode } from '../src/crypto/base32.js';
import { hashPassword } from '../src/crypto/password.js';
import { sessionCookieOf, testApp, type TestApp } from './helpers.js';

const EMAIL = 'ada@example.com';
const PASSWORD = 'correct horse battery';

async function signup(t: TestApp, email = EMAIL, password = PASSWORD) {
  // Signup is enumeration-safe and does not auto-login; log in to get a session.
  await request(t.app).post('/api/auth/signup').send({ email, password }).expect(202);
  const res = await request(t.app).post('/api/auth/login').send({ email, password });
  expect(res.status).toBe(200);
  return { cookie: sessionCookieOf(res), csrf: res.body.csrfToken as string };
}

describe('signup and login', () => {
  it('signs up (enumeration-safe 202), then login sets a session cookie and a verify email is enqueued', async () => {
    const t = testApp();
    const res = await request(t.app).post('/api/auth/signup').send({ email: EMAIL, password: PASSWORD });
    expect(res.status).toBe(202);
    expect(res.body).toEqual({ ok: true }); // no session, no account details leaked
    expect(res.headers['set-cookie']).toBeUndefined();

    const login = await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: PASSWORD });
    expect(login.status).toBe(200);
    const cookie = sessionCookieOf(login);
    expect(login.headers['set-cookie']![0]).toMatch(/HttpOnly/);
    expect(login.headers['set-cookie']![0]).toMatch(/SameSite=Lax/);
    await request(t.app).get('/api/me').set('Cookie', cookie).expect(200);

    const mails = await t.drainMail();
    expect(mails).toHaveLength(1);
    expect(mails[0]!.to).toBe(EMAIL);
  });

  it('signup is enumeration-safe on a taken address; rejects bad emails, short passwords', async () => {
    const t = testApp();
    const fresh = await request(t.app).post('/api/auth/signup').send({ email: EMAIL, password: PASSWORD });
    // A repeat with the same address is indistinguishable from the first attempt.
    const dup = await request(t.app).post('/api/auth/signup').send({ email: EMAIL, password: PASSWORD });
    expect(dup.status).toBe(fresh.status);
    expect(dup.body).toEqual(fresh.body);
    // and it did not create a second account: the original login still works
    await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: PASSWORD }).expect(200);
    expect((await request(t.app).post('/api/auth/signup').send({ email: 'nope', password: PASSWORD })).status).toBe(400);
    expect((await request(t.app).post('/api/auth/signup').send({ email: 'x@y.io', password: 'short' })).status).toBe(400);
  });

  it('signup pays the Argon2 cost on the taken branch too, so the floor is not the only cover', async () => {
    // withMinDuration is max(floor, work), not a fixed budget: the new-account
    // branch hashes a password and the taken branch did not. On the deployed
    // 0.25 vCPU task the hash outruns the 100ms floor under load, and the two
    // branches separate into an email-existence oracle. Timing the branches
    // against each other is load-dependent and flaky; timing the taken branch
    // against one real hash is not.
    const t = testApp();
    t.ctx.config.uniformDelayMs = 0; // strip the floor so the branch's own cost shows
    await request(t.app).post('/api/auth/signup').send({ email: EMAIL, password: PASSWORD }).expect(202);

    const hashStart = Date.now();
    await hashPassword(PASSWORD);
    const hashMs = Date.now() - hashStart;

    const takenStart = Date.now();
    await request(t.app).post('/api/auth/signup').send({ email: EMAIL, password: PASSWORD }).expect(202);
    const takenMs = Date.now() - takenStart;

    expect(takenMs).toBeGreaterThanOrEqual(hashMs / 2);
  });

  it('signup on a taken address emails the owner a reset link, not silence', async () => {
    const t = testApp();
    await request(t.app).post('/api/auth/signup').send({ email: EMAIL, password: PASSWORD }).expect(202);
    await request(t.app).post('/api/auth/signup').send({ email: EMAIL, password: 'a-different-password' }).expect(202);
    const mails = await t.drainMail();
    // One verification mail for the real signup, one notice for the taken retry.
    expect(mails).toHaveLength(2);
    expect(mails[1]!.to).toBe(EMAIL);
    expect(mails[1]!.text).toContain('/reset?token=');
    // The notice must not become a password-change oracle: the reset link is a
    // token, and the attacker's chosen password was never applied.
    await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: 'a-different-password' }).expect(401);
    await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: PASSWORD }).expect(200);
  });

  it('logs in with correct password, rejects wrong password and unknown user identically', async () => {
    const t = testApp();
    await signup(t);
    expect((await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: PASSWORD })).status).toBe(200);
    const wrong = await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: 'wrong password' });
    const unknown = await request(t.app).post('/api/auth/login').send({ email: 'ghost@example.com', password: PASSWORD });
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(unknown.body).toEqual(wrong.body);
  });

  it('CSRF: mutations without the header are rejected', async () => {
    const t = testApp();
    const { cookie } = await signup(t);
    const res = await request(t.app).post('/api/account/email').set('Cookie', cookie).send({ email: 'new@example.com' });
    expect(res.status).toBe(403);
  });

  it('CSRF: a same-length token with a non-ASCII byte is a 403, not a 500', async () => {
    // Node parses header values as latin1: one char >= 0x80 is one UTF-16
    // unit but two UTF-8 bytes, so a JS-length comparison passes and
    // timingSafeEqual throws — reporting an authorization failure as a
    // server fault, and handing any unauthenticated client a 500 generator.
    const t = testApp();
    const { cookie, csrf } = await signup(t);
    const sameLength = 'Ã' + csrf.slice(1);
    expect(sameLength.length).toBe(csrf.length);
    const res = await request(t.app)
      .post('/api/account/email')
      .set('Cookie', cookie)
      .set('x-csrf-token', sameLength)
      .send({ email: 'new@example.com' });
    expect(res.status).toBe(403);
  });

  it('a malformed percent-escape in an unrelated cookie does not break the request', async () => {
    // decodeURIComponent('100%') throws URIError, and sessionLoader runs for
    // every request — one stray '%' in any cookie on this host would
    // otherwise 500 the whole app for that browser.
    const t = testApp();
    const { cookie } = await signup(t);
    await request(t.app).get('/api/me').set('Cookie', `promo=100%; ${cookie}`).expect(200);
    await request(t.app).get('/api/me').set('Cookie', 'x=%').expect(401);
  });

  it('logout destroys the session', async () => {
    const t = testApp();
    const { cookie, csrf } = await signup(t);
    await request(t.app).post('/api/auth/logout').set('Cookie', cookie).set('x-csrf-token', csrf).expect(200);
    await request(t.app).get('/api/me').set('Cookie', cookie).expect(401);
  });
});

describe('password reset', () => {
  it('is enumeration-safe: identical response shape and minimum duration for both paths', async () => {
    const t = testApp();
    await signup(t);
    const timed = async (email: string) => {
      const start = Date.now();
      const res = await request(t.app).post('/api/auth/forgot').send({ email });
      return { res, ms: Date.now() - start };
    };
    const exists = await timed(EMAIL);
    const missing = await timed('ghost@example.com');
    expect(exists.res.status).toBe(202);
    expect(missing.res.status).toBe(202);
    expect(missing.res.body).toEqual(exists.res.body);
    // uniformDelayMs = 50 in the test config
    expect(exists.ms).toBeGreaterThanOrEqual(45);
    expect(missing.ms).toBeGreaterThanOrEqual(45);
    // exactly one email actually went out (to the real account)
    expect(await t.drainMail()).toHaveLength(2); // signup verify + reset
  });

  it('resets the password once, invalidates sessions, and rejects reuse', async () => {
    const t = testApp();
    const { cookie } = await signup(t);
    await request(t.app).post('/api/auth/forgot').send({ email: EMAIL }).expect(202);
    const token = await t.lastToken();

    const newPassword = 'brand new password';
    await request(t.app).post('/api/auth/reset').send({ token, password: newPassword }).expect(200);

    // sessions invalidated
    await request(t.app).get('/api/me').set('Cookie', cookie).expect(401);
    // old password dead, new one works
    await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: PASSWORD }).expect(401);
    await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: newPassword }).expect(200);
    // single use
    await request(t.app).post('/api/auth/reset').send({ token, password: 'another password' }).expect(400);
  });

  it('cancels a pending email change, so takeover does not survive the remediation', async () => {
    // verify-email needs no session at all — the token is the whole
    // authorization, for 24h. An attacker who queued a change to their own
    // address while holding a session would otherwise still own the login
    // afterwards: reset kills their session and changes the password, then
    // their old link flips users.email to them and /forgot does the rest.
    const t = testApp();
    const { cookie, csrf } = await signup(t);
    await request(t.app)
      .post('/api/account/email')
      .set('Cookie', cookie)
      .set('x-csrf-token', csrf)
      .send({ email: 'attacker@example.com', password: PASSWORD })
      .expect(202);
    const changeToken = await t.lastToken();

    await request(t.app).post('/api/auth/forgot').send({ email: EMAIL }).expect(202);
    const resetToken = await t.lastToken();
    const newPassword = 'brand new password';
    await request(t.app).post('/api/auth/reset').send({ token: resetToken, password: newPassword }).expect(200);

    await request(t.app).post('/api/auth/verify-email').send({ token: changeToken }).expect(400);
    const login = await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: newPassword }).expect(200);
    expect(login.body.user.email).toBe(EMAIL);
    expect(login.body.user.pendingEmail).toBeNull();
  });

  it('does not strand an unverified signup: the original verification link still works after a reset', async () => {
    // Cancelling an attacker's queued address change was done by revoking the
    // whole verify_email purpose, which also burned the token minted at signup
    // — and there is no resend route, so an account that resets before opening
    // its first verification link could never verify. Clearing pendingEmail is
    // what cancels a change; the signup token is not a change.
    const t = testApp();
    await request(t.app).post('/api/auth/signup').send({ email: EMAIL, password: PASSWORD }).expect(202);
    const verifyToken = await t.lastToken();

    await request(t.app).post('/api/auth/forgot').send({ email: EMAIL }).expect(202);
    const newPassword = 'brand new password';
    await request(t.app).post('/api/auth/reset').send({ token: await t.lastToken(), password: newPassword }).expect(200);

    await request(t.app).post('/api/auth/verify-email').send({ token: verifyToken }).expect(200);
    const login = await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: newPassword }).expect(200);
    expect(login.body.user.emailVerified).toBe(true);
  });

  it('rejects expired tokens', async () => {
    const t = testApp();
    await signup(t);
    await request(t.app).post('/api/auth/forgot').send({ email: EMAIL });
    const token = await t.lastToken();
    t.clock.advance(16 * 60 * 1000); // past the 15-minute TTL
    await request(t.app).post('/api/auth/reset').send({ token, password: 'whatever works' }).expect(400);
  });

  it('using one reset token revokes its siblings', async () => {
    const t = testApp();
    await signup(t);
    await request(t.app).post('/api/auth/forgot').send({ email: EMAIL });
    const first = await t.lastToken();
    await request(t.app).post('/api/auth/forgot').send({ email: EMAIL });
    const second = await t.lastToken();
    expect(second).not.toBe(first);
    await request(t.app).post('/api/auth/reset').send({ token: second, password: 'new password 1' }).expect(200);
    await request(t.app).post('/api/auth/reset').send({ token: first, password: 'new password 2' }).expect(400);
  });
});

describe('email verification and change', () => {
  it('verifies the signup address', async () => {
    const t = testApp();
    const { cookie } = await signup(t);
    const token = await t.lastToken();
    await request(t.app).post('/api/auth/verify-email').send({ token }).expect(200);
    const me = await request(t.app).get('/api/me').set('Cookie', cookie);
    expect(me.body.user.emailVerified).toBe(true);
    // single use
    await request(t.app).post('/api/auth/verify-email').send({ token }).expect(400);
  });

  it('email change: old address stays active until the new one is confirmed', async () => {
    const t = testApp();
    const { cookie, csrf } = await signup(t);
    const NEW = 'ada.new@example.com';
    await request(t.app)
      .post('/api/account/email')
      .set('Cookie', cookie)
      .set('x-csrf-token', csrf)
      .send({ email: NEW, password: PASSWORD })
      .expect(202);

    // still logs in with the OLD address; new address not active yet
    await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: PASSWORD }).expect(200);
    await request(t.app).post('/api/auth/login').send({ email: NEW, password: PASSWORD }).expect(401);

    const mails = await t.drainMail();
    expect(mails[mails.length - 1]!.to).toBe(NEW); // verification goes to the new address
    const token = await t.lastToken();
    const verified = await request(t.app).post('/api/auth/verify-email').send({ token });
    expect(verified.status).toBe(200);

    // now the new address is the login and the old one is gone
    await request(t.app).post('/api/auth/login').send({ email: NEW, password: PASSWORD }).expect(200);
    await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: PASSWORD }).expect(401);
  });

  it('a superseded change token is rejected', async () => {
    const t = testApp();
    const { cookie, csrf } = await signup(t);
    const change = (email: string) =>
      request(t.app).post('/api/account/email').set('Cookie', cookie).set('x-csrf-token', csrf).send({ email, password: PASSWORD });
    await change('first@example.com').expect(202);
    const firstToken = await t.lastToken();
    await change('second@example.com').expect(202);
    await request(t.app).post('/api/auth/verify-email').send({ token: firstToken }).expect(400);
  });

  it('a duplicate-address conflict at confirm time does not burn the token', async () => {
    // Someone else registering the address during the 24h window is a
    // recoverable conflict, not an attack. Consuming the single-use token
    // before that check left the user with a dead link and no way back except
    // restarting the change.
    const t = testApp();
    const { cookie, csrf } = await signup(t);
    const CONTESTED = 'rival@example.com';
    await request(t.app)
      .post('/api/account/email')
      .set('Cookie', cookie)
      .set('x-csrf-token', csrf)
      .send({ email: CONTESTED, password: PASSWORD })
      .expect(202);
    const token = await t.lastToken();
    await request(t.app).post('/api/auth/signup').send({ email: CONTESTED, password: PASSWORD }).expect(202);

    await request(t.app).post('/api/auth/verify-email').send({ token }).expect(409);
    // Still live: a 400 here would mean the token was spent on the conflict.
    await request(t.app).post('/api/auth/verify-email').send({ token }).expect(409);
  });

  it('moving the login address requires the account password, not merely a session', async () => {
    // The address is the root of every mailed recovery path, so a cookie-only
    // attacker who could move it reached the password in four calls: change ->
    // verify (needs no password) -> forgot -> reset, at which point they CHOSE
    // the password and the "a stolen cookie alone cannot enroll an
    // authenticator" property of /totp/setup was worth nothing.
    const t = testApp();
    const { cookie, csrf } = await signup(t);
    const move = (body: object) =>
      request(t.app).post('/api/account/email').set('Cookie', cookie).set('x-csrf-token', csrf).send(body);
    await move({ email: 'attacker@example.com' }).expect(401);
    await move({ email: 'attacker@example.com', password: 'not the password' }).expect(401);

    const user = await t.ctx.store.users.findByEmail(EMAIL);
    expect(user!.pendingEmail).toBeNull();
    expect(await t.drainMail()).toHaveLength(1); // the signup verification, and nothing else
  });

  it('a confirmed address change tells the old inbox, which can put the account back', async () => {
    // An attacker who knows the password (stuffing, phishing) passes the
    // re-auth above. Moving the address first made every later notice — the
    // undo_totp escape hatch included — arrive in their own inbox, while the
    // owner's /forgot went to an address on no account: permanent lockout with
    // no notification at any point.
    const t = testApp();
    const attacker = await signup(t);
    const EVIL = 'attacker@example.com';
    await request(t.app)
      .post('/api/account/email')
      .set('Cookie', attacker.cookie)
      .set('x-csrf-token', attacker.csrf)
      .send({ email: EVIL, password: PASSWORD })
      .expect(202);
    await request(t.app).post('/api/auth/verify-email').send({ token: await t.lastToken() }).expect(200);

    const mails = await t.drainMail();
    expect(mails[mails.length - 1]!.to).toBe(EMAIL); // the notice goes to the address left behind
    const undoToken = await t.lastToken();

    // The attacker now enrolls a factor, and *its* notice does land on them.
    const setup = await request(t.app)
      .post('/api/security/totp/setup')
      .set('Cookie', attacker.cookie)
      .set('x-csrf-token', attacker.csrf)
      .send({ password: PASSWORD })
      .expect(200);
    await request(t.app)
      .post('/api/security/totp/activate')
      .set('Cookie', attacker.cookie)
      .set('x-csrf-token', attacker.csrf)
      .send({ code: totp(base32Decode(setup.body.secret as string), t.clock.now.getTime() / 1000) })
      .expect(200);
    const afterEnroll = await t.drainMail();
    expect(afterEnroll[afterEnroll.length - 1]!.to).toBe(EVIL);

    // The owner's documented remedy produces nothing: no account has that address.
    await request(t.app).post('/api/auth/forgot').send({ email: EMAIL }).expect(202);
    expect(await t.drainMail()).toHaveLength(afterEnroll.length);

    // The link in the old inbox is the way back, and it takes the factor the
    // mover enrolled with it.
    const undo = await request(t.app).post('/api/auth/undo-email').send({ token: undoToken }).expect(200);
    expect(undo.body.email).toBe(EMAIL);
    await request(t.app).post('/api/auth/login').send({ email: EVIL, password: PASSWORD }).expect(401);
    const back = await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: PASSWORD }).expect(200);
    expect(back.body.mfaPending).toBe(false);
    expect(back.body.user.totpEnabled).toBe(false);
    const user = await t.ctx.store.users.findByEmail(EMAIL);
    expect(await t.ctx.store.recoveryCodes.countUnused(user!.id)).toBe(0);
    await request(t.app).get('/api/me').set('Cookie', attacker.cookie).expect(401);
    // single use
    await request(t.app).post('/api/auth/undo-email').send({ token: undoToken }).expect(400);
  });

  it('rate-limits the email-change existence oracle', async () => {
    // 409-vs-202 answers "does this address exist" with no side effect and no
    // cleanup. Every /api/auth/* route is throttled; this one was not, so one
    // throwaway account bought the whole user directory at network speed.
    const t = testApp();
    const { cookie, csrf } = await signup(t);
    t.ctx.config.rateLimit = { limit: 2, windowMs: 60_000 };
    const probe = (email: string) =>
      request(t.app).post('/api/account/email').set('Cookie', cookie).set('x-csrf-token', csrf).send({ email, password: PASSWORD });
    await probe('probe-a@example.com').expect(202);
    await probe('probe-b@example.com').expect(202);
    await probe('probe-c@example.com').expect(429);
  });
});

describe('TOTP MFA', () => {
  async function enroll(t: TestApp) {
    const { cookie, csrf } = await signup(t);
    const setup = await request(t.app)
      .post('/api/security/totp/setup')
      .set('Cookie', cookie)
      .set('x-csrf-token', csrf)
      .send({ password: PASSWORD })
      .expect(200);
    expect(setup.body.otpauthUri).toMatch(/^otpauth:\/\/totp\//);
    expect(setup.body.qrSvg).toContain('<svg');
    const secret = base32Decode(setup.body.secret as string);
    const code = totp(secret, t.clock.now.getTime() / 1000);
    const activate = await request(t.app)
      .post('/api/security/totp/activate')
      .set('Cookie', cookie)
      .set('x-csrf-token', csrf)
      .send({ code })
      .expect(200);
    const recoveryCodes = activate.body.recoveryCodes as string[];
    expect(recoveryCodes).toHaveLength(10);
    return { cookie, csrf, secret, recoveryCodes };
  }

  it('stores the pending secret sealed at rest, not plaintext', async () => {
    const t = testApp();
    const { cookie, csrf } = await signup(t);
    const setup = await request(t.app)
      .post('/api/security/totp/setup')
      .set('Cookie', cookie)
      .set('x-csrf-token', csrf)
      .send({ password: PASSWORD })
      .expect(200);
    const plainBase32 = setup.body.secret as string;
    const user = await t.ctx.store.users.findByEmail(EMAIL);
    expect(user!.totpPendingSecret).not.toBeNull();
    expect(user!.totpPendingSecret).not.toBe(plainBase32);
    expect(user!.totpPendingSecret).not.toContain(plainBase32);
  });

  it('enrolls, then login requires the TOTP step-up', async () => {
    const t = testApp();
    const { secret } = await enroll(t);

    const login = await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: PASSWORD }).expect(200);
    expect(login.body.mfaPending).toBe(true);
    const cookie = sessionCookieOf(login);
    const csrf = login.body.csrfToken as string;

    // MFA-pending session cannot use authenticated endpoints
    await request(t.app)
      .post('/api/account/email')
      .set('Cookie', cookie)
      .set('x-csrf-token', csrf)
      .send({ email: 'x@example.com' })
      .expect(401);

    t.clock.advance(60_000); // move past the enrollment code's time-step
    const code = totp(secret, t.clock.now.getTime() / 1000);
    const step = await request(t.app)
      .post('/api/auth/totp')
      .set('Cookie', cookie)
      .set('x-csrf-token', csrf)
      .send({ code })
      .expect(200);
    expect(step.body.mfaPending).toBe(false);
  });

  it('rejects replayed codes from the same time-step', async () => {
    const t = testApp();
    const { secret } = await enroll(t);
    t.clock.advance(60_000);

    const login = async () => {
      const res = await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: PASSWORD });
      return { cookie: sessionCookieOf(res), csrf: res.body.csrfToken as string };
    };
    const code = totp(secret, t.clock.now.getTime() / 1000);

    const s1 = await login();
    await request(t.app).post('/api/auth/totp').set('Cookie', s1.cookie).set('x-csrf-token', s1.csrf).send({ code }).expect(200);

    // same code, same step, new session: replay must be rejected
    const s2 = await login();
    await request(t.app).post('/api/auth/totp').set('Cookie', s2.cookie).set('x-csrf-token', s2.csrf).send({ code }).expect(401);

    // next step works again
    t.clock.advance(30_000);
    const next = totp(secret, t.clock.now.getTime() / 1000);
    await request(t.app).post('/api/auth/totp').set('Cookie', s2.cookie).set('x-csrf-token', s2.csrf).send({ code: next }).expect(200);
  });

  it('TOCTOU: two concurrent uses of the same code, exactly one succeeds', async () => {
    const t = testApp();
    const { secret } = await enroll(t);
    t.clock.advance(60_000);
    const code = totp(secret, t.clock.now.getTime() / 1000);

    const login = async () => {
      const res = await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: PASSWORD });
      return { cookie: sessionCookieOf(res), csrf: res.body.csrfToken as string };
    };
    const [a, b] = await Promise.all([login(), login()]);
    const step = (s: { cookie: string; csrf: string }) =>
      request(t.app).post('/api/auth/totp').set('Cookie', s.cookie).set('x-csrf-token', s.csrf).send({ code });

    const results = await Promise.all([step(a), step(b)]);
    const statuses = results.map((r) => r.status).sort();
    expect(statuses).toEqual([200, 401]); // the atomic counter advance rejects the replayer
  });

  it('recovery codes complete the step-up and are single-use', async () => {
    const t = testApp();
    const { recoveryCodes } = await enroll(t);
    const rc = recoveryCodes[0]!;

    const login = async () => {
      const res = await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: PASSWORD });
      return { cookie: sessionCookieOf(res), csrf: res.body.csrfToken as string };
    };

    const s1 = await login();
    await request(t.app).post('/api/auth/totp').set('Cookie', s1.cookie).set('x-csrf-token', s1.csrf).send({ code: rc }).expect(200);

    const s2 = await login();
    await request(t.app).post('/api/auth/totp').set('Cookie', s2.cookie).set('x-csrf-token', s2.csrf).send({ code: rc }).expect(401);
    // a different unused code still works
    await request(t.app)
      .post('/api/auth/totp')
      .set('Cookie', s2.cookie)
      .set('x-csrf-token', s2.csrf)
      .send({ code: recoveryCodes[1]! })
      .expect(200);
  });

  it('activation rejects a wrong code and leaves TOTP disabled', async () => {
    const t = testApp();
    const { cookie, csrf } = await signup(t);
    await request(t.app)
      .post('/api/security/totp/setup')
      .set('Cookie', cookie)
      .set('x-csrf-token', csrf)
      .send({ password: PASSWORD })
      .expect(200);
    await request(t.app)
      .post('/api/security/totp/activate')
      .set('Cookie', cookie)
      .set('x-csrf-token', csrf)
      .send({ code: '000000' })
      .expect(401);
    const me = await request(t.app).get('/api/me').set('Cookie', cookie);
    expect(me.body.user.totpEnabled).toBe(false);
    // plain login still works without a step-up
    const login = await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: PASSWORD }).expect(200);
    expect(login.body.mfaPending).toBe(false);
  });

  it('enrollment requires the account password, not merely a session', async () => {
    // A hijacked session could otherwise enroll the attacker's authenticator
    // on an MFA-less account — and reset deliberately does not clear TOTP, so
    // the owner's own remediation cannot undo it. Permanent lockout.
    const t = testApp();
    const { cookie, csrf } = await signup(t);
    const setup = (body: object) =>
      request(t.app).post('/api/security/totp/setup').set('Cookie', cookie).set('x-csrf-token', csrf).send(body);
    await setup({}).expect(401);
    await setup({ password: 'not the password' }).expect(401);
    const user = await t.ctx.store.users.findByEmail(EMAIL);
    expect(user!.totpPendingSecret).toBeNull();
  });

  it('TOTP can be disabled and recovery codes regenerated — enrollment is not a one-way door', async () => {
    const t = testApp();
    const { cookie, csrf, recoveryCodes } = await enroll(t);
    const me = await request(t.app).get('/api/me').set('Cookie', cookie).expect(200);
    expect(me.body.user.recoveryCodesRemaining).toBe(10); // visible before the last one is spent

    const regen = await request(t.app)
      .post('/api/security/totp/recovery-codes')
      .set('Cookie', cookie)
      .set('x-csrf-token', csrf)
      .send({ password: PASSWORD })
      .expect(200);
    expect(regen.body.recoveryCodes).toHaveLength(10);
    expect(regen.body.recoveryCodes).not.toContain(recoveryCodes[0]);

    const disable = (body: object) =>
      request(t.app).post('/api/security/totp/disable').set('Cookie', cookie).set('x-csrf-token', csrf).send(body);
    await disable({ password: 'not the password' }).expect(401);
    await disable({ password: PASSWORD }).expect(200);

    const login = await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: PASSWORD }).expect(200);
    expect(login.body.mfaPending).toBe(false);
    expect(login.body.user.totpEnabled).toBe(false);
    // codes go with the secret; a later re-enrollment must not honour old ones
    const user = await t.ctx.store.users.findByEmail(EMAIL);
    expect(await t.ctx.store.recoveryCodes.countUnused(user!.id)).toBe(0);
  });

  it('the enrollment notice lets the inbox undo a hostile enrollment by someone who knew the password', async () => {
    // Password re-auth on /setup only stops cookie theft. Against credential
    // stuffing or phishing the attacker HAS the password: they enroll their own
    // authenticator, and the owner's documented remedy — forgot + reset, then
    // log in — lands on an mfaPending session that requireAuth rejects, so
    // /totp/disable is out of reach and the account is permanently lost.
    const t = testApp();
    const attacker = await signup(t); // a session obtained with the stolen password
    const setup = await request(t.app)
      .post('/api/security/totp/setup')
      .set('Cookie', attacker.cookie)
      .set('x-csrf-token', attacker.csrf)
      .send({ password: PASSWORD })
      .expect(200);
    const secret = base32Decode(setup.body.secret as string);
    await request(t.app)
      .post('/api/security/totp/activate')
      .set('Cookie', attacker.cookie)
      .set('x-csrf-token', attacker.csrf)
      .send({ code: totp(secret, t.clock.now.getTime() / 1000) })
      .expect(200);

    const undoToken = await t.lastToken(); // the notice mailed to the account address

    // The owner controls the password and the inbox, and it is still not enough.
    const NEW_PASSWORD = 'a completely different passphrase';
    await request(t.app).post('/api/auth/forgot').send({ email: EMAIL }).expect(202);
    await request(t.app).post('/api/auth/reset').send({ token: await t.lastToken(), password: NEW_PASSWORD }).expect(200);
    const locked = await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: NEW_PASSWORD }).expect(200);
    expect(locked.body.mfaPending).toBe(true);
    await request(t.app)
      .post('/api/security/totp/disable')
      .set('Cookie', sessionCookieOf(locked))
      .set('x-csrf-token', locked.body.csrfToken)
      .send({ password: NEW_PASSWORD })
      .expect(401);

    // The mailed link is the way back, and takes the attacker's codes and
    // session with it. An inbox-only attacker gains nothing: it revokes a
    // factor, it never satisfies one.
    await request(t.app).post('/api/auth/undo-totp').send({ token: undoToken }).expect(200);
    const back = await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: NEW_PASSWORD }).expect(200);
    expect(back.body.mfaPending).toBe(false);
    expect(back.body.user.totpEnabled).toBe(false);
    const user = await t.ctx.store.users.findByEmail(EMAIL);
    expect(await t.ctx.store.recoveryCodes.countUnused(user!.id)).toBe(0);
    await request(t.app).get('/api/me').set('Cookie', attacker.cookie).expect(401);
    // single use
    await request(t.app).post('/api/auth/undo-totp').send({ token: undoToken }).expect(400);
  });
});

describe('sessions', () => {
  it('lists active sessions and revokes one', async () => {
    const t = testApp();
    const { cookie, csrf } = await signup(t);
    const other = await request(t.app).post('/api/auth/login').send({ email: EMAIL, password: PASSWORD });
    const otherCookie = sessionCookieOf(other);

    const list = await request(t.app).get('/api/security/sessions').set('Cookie', cookie).expect(200);
    expect(list.body.sessions).toHaveLength(2);
    const target = list.body.sessions.find((s: { current: boolean }) => !s.current);

    await request(t.app)
      .delete(`/api/security/sessions/${target.id}`)
      .set('Cookie', cookie)
      .set('x-csrf-token', csrf)
      .expect(200);
    await request(t.app).get('/api/me').set('Cookie', otherCookie).expect(401);
    await request(t.app).get('/api/me').set('Cookie', cookie).expect(200);
  });

  it('cannot revoke another user\'s session', async () => {
    const t = testApp();
    const a = await signup(t, 'a@example.com');
    const b = await signup(t, 'b@example.com');
    const list = await request(t.app).get('/api/security/sessions').set('Cookie', b.cookie).expect(200);
    await request(t.app)
      .delete(`/api/security/sessions/${list.body.sessions[0].id}`)
      .set('Cookie', a.cookie)
      .set('x-csrf-token', a.csrf)
      .expect(404);
  });

  it('sessions expire', async () => {
    const t = testApp();
    const { cookie } = await signup(t);
    t.clock.advance(25 * 60 * 60 * 1000);
    await request(t.app).get('/api/me').set('Cookie', cookie).expect(401);
  });
});

describe('email normalization', () => {
  it('login and signup treat case and whitespace as the same account', async () => {
    // users.email is a plain case-sensitive UNIQUE column. Without
    // normalization, signing up as Alice@Example.com and then logging in as
    // alice@example.com is a 401 for an account that exists — and signing up
    // again with the lowercase form silently creates a second one.
    const t = testApp();
    await request(t.app)
      .post('/api/auth/signup')
      .send({ email: 'Ada@Example.com ', password: PASSWORD })
      .expect(202);

    const res = await request(t.app).post('/api/auth/login').send({ email: 'ada@example.com', password: PASSWORD });
    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe('ada@example.com');

    // The second signup must find the existing account, not create a rival.
    await request(t.app).post('/api/auth/signup').send({ email: 'ADA@EXAMPLE.COM', password: PASSWORD }).expect(202);
    const again = await request(t.app).post('/api/auth/login').send({ email: 'ada@example.com', password: PASSWORD });
    expect(again.status).toBe(200);
    // meBody carries no user id, so comparing again.body.user.id to
    // res.body.user.id compared two undefineds and pinned nothing. Observe the
    // branch instead: the taken-address path mails a reset notice, the
    // create path mails a verification.
    const mails = await t.drainMail();
    expect(mails).toHaveLength(2);
    expect(mails[1]!.subject).toMatch(/tried to create/);
    expect(await t.ctx.store.users.findByEmail('ada@example.com')).not.toBeNull();
  });
});

describe('rate limiting', () => {
  it('throttles repeated auth attempts', async () => {
    const t = testApp();
    t.ctx.config.rateLimit = { limit: 3, windowMs: 60_000 };
    for (let i = 0; i < 3; i++) {
      await request(t.app).post('/api/auth/login').send({ email: 'x@y.io', password: 'nope nope' }).expect(401);
    }
    await request(t.app).post('/api/auth/login').send({ email: 'x@y.io', password: 'nope nope' }).expect(429);
  });

  it('buckets by the matched route, not the spelling of the URL', async () => {
    // Express routes case-insensitively and ignores a trailing slash by
    // default, so all of these reach the same handler while reporting a
    // different req.path. Keyed on req.path that was a fresh bucket per
    // casing — 2^12 of them on this route — i.e. no limit at all, and the
    // limiter is the only brute-force control there is (no lockout).
    const t = testApp();
    t.ctx.config.rateLimit = { limit: 2, windowMs: 60_000 };
    const attempt = (path: string) =>
      request(t.app).post(path).send({ email: 'x@y.io', password: 'nope nope' });
    await attempt('/api/auth/login').expect(401);
    await attempt('/api/auth/login').expect(401);
    await attempt('/api/auth/login').expect(429);
    await attempt('/API/Auth/LOGIN').expect(429);
    await attempt('/api/auth/login/').expect(429);
  });
});
