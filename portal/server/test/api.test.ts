import { describe, expect, it } from 'vitest';
import request from 'supertest';
import { totp } from '../src/crypto/totp.js';
import { base32Decode } from '../src/crypto/base32.js';
import { sessionCookieOf, testApp, type TestApp } from './helpers.js';

const EMAIL = 'ada@example.com';
const PASSWORD = 'correct horse battery';

async function signup(t: TestApp, email = EMAIL, password = PASSWORD) {
  const res = await request(t.app).post('/api/auth/signup').send({ email, password });
  expect(res.status).toBe(201);
  return { cookie: sessionCookieOf(res), csrf: res.body.csrfToken as string };
}

describe('signup and login', () => {
  it('signs up, sets a session cookie, and enqueues a verification email', async () => {
    const t = testApp();
    const res = await request(t.app).post('/api/auth/signup').send({ email: EMAIL, password: PASSWORD });
    expect(res.status).toBe(201);
    expect(res.body.user).toMatchObject({ email: EMAIL, emailVerified: false, totpEnabled: false });
    const cookie = sessionCookieOf(res);
    expect(res.headers['set-cookie']![0]).toMatch(/HttpOnly/);
    expect(res.headers['set-cookie']![0]).toMatch(/SameSite=Lax/);

    const me = await request(t.app).get('/api/me').set('Cookie', cookie);
    expect(me.status).toBe(200);

    const mails = await t.drainMail();
    expect(mails).toHaveLength(1);
    expect(mails[0]!.to).toBe(EMAIL);
  });

  it('rejects duplicate signups, bad emails, short passwords', async () => {
    const t = testApp();
    await signup(t);
    expect((await request(t.app).post('/api/auth/signup').send({ email: EMAIL, password: PASSWORD })).status).toBe(409);
    expect((await request(t.app).post('/api/auth/signup').send({ email: 'nope', password: PASSWORD })).status).toBe(400);
    expect((await request(t.app).post('/api/auth/signup').send({ email: 'x@y.io', password: 'short' })).status).toBe(400);
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
      .send({ email: NEW })
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
      request(t.app).post('/api/account/email').set('Cookie', cookie).set('x-csrf-token', csrf).send({ email });
    await change('first@example.com').expect(202);
    const firstToken = await t.lastToken();
    await change('second@example.com').expect(202);
    await request(t.app).post('/api/auth/verify-email').send({ token: firstToken }).expect(400);
  });
});

describe('TOTP MFA', () => {
  async function enroll(t: TestApp) {
    const { cookie, csrf } = await signup(t);
    const setup = await request(t.app)
      .post('/api/security/totp/setup')
      .set('Cookie', cookie)
      .set('x-csrf-token', csrf)
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
    await request(t.app).post('/api/security/totp/setup').set('Cookie', cookie).set('x-csrf-token', csrf).expect(200);
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

describe('rate limiting', () => {
  it('throttles repeated auth attempts', async () => {
    const t = testApp();
    t.ctx.config.rateLimit = { limit: 3, windowMs: 60_000 };
    for (let i = 0; i < 3; i++) {
      await request(t.app).post('/api/auth/login').send({ email: 'x@y.io', password: 'nope nope' }).expect(401);
    }
    await request(t.app).post('/api/auth/login').send({ email: 'x@y.io', password: 'nope nope' }).expect(429);
  });
});
