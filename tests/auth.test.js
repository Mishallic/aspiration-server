import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { MAX_FAILED_LOGINS } from '../src/routes/auth.js';
import { PASSWORD, createTestApp, lastEmail, signUp, verifyLikeAThirdParty } from './helpers.js';

describe('sign-up', () => {
  let t;
  beforeAll(async () => {
    t = await createTestApp();
  });
  afterAll(() => t.close());

  test('creates the user, returns a session and sends a verification email', async () => {
    const res = await t.api().post('/v1/auth/signup').send({
      email: '  Ada@Example.COM ',
      password: PASSWORD,
      firstName: 'Ada',
    });
    expect(res.status).toBe(201);
    expect(res.body.user).toMatchObject({
      email: 'ada@example.com',
      firstName: 'Ada',
      emailVerified: false,
      role: 'user',
      hasPassword: true,
    });
    expect(res.body).toMatchObject({ tokenType: 'Bearer', expiresIn: 900 });
    expect(res.body.refreshToken).toMatch(/^rt_/);
    expect(lastEmail(t.ctx)).toMatchObject({ to: 'ada@example.com', subject: expect.stringMatching(/Confirm/) });
  });

  test('the access token verifies with only the public JWKS', async () => {
    const { user, accessToken } = await signUp(t.app, { email: 'jwks@example.com' });
    const { payload, protectedHeader } = await verifyLikeAThirdParty(t.app, accessToken, t.config);
    expect(protectedHeader.alg).toBe('RS256');
    expect(payload).toMatchObject({ sub: user.id, email: 'jwks@example.com', email_verified: false, role: 'user' });
    expect(payload.exp - payload.iat).toBe(900);
  });

  test('stores an Argon2id hash, never the password', async () => {
    const user = await t.ctx.models.User.findOne({ where: { email: 'ada@example.com' } });
    expect(user.passwordHash).toMatch(/^\$argon2id\$/);
    expect(user.passwordHash).not.toContain(PASSWORD);
  });

  test('responses never include secrets', async () => {
    const { user } = await signUp(t.app, { email: 'secrets@example.com' });
    for (const field of ['passwordHash', 'failedLoginCount', 'lockedUntil', 'tokensValidAfter']) {
      expect(user[field]).toBeUndefined();
    }
  });

  test('rejects a duplicate email in any letter case', async () => {
    const res = await t.api().post('/v1/auth/signup').send({ email: 'ADA@example.com', password: PASSWORD });
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('email_taken');
  });

  test.each([
    [{}, 'email'],
    [{ email: 'not-an-email', password: PASSWORD }, 'email'],
    [{ email: 'short@example.com', password: 'short' }, 'password'],
    [{ email: 'long@example.com', password: 'x'.repeat(257) }, 'password'],
    [{ email: 'type@example.com', password: 12345678 }, 'password'],
  ])('returns 400 with field details for %o', async (body, field) => {
    const res = await t.api().post('/v1/auth/signup').send(body);
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('invalid_request');
    expect(res.body.error.details.map((d) => d.field)).toContain(field);
  });

  test('cannot self-assign a role or verified email', async () => {
    const res = await t.api().post('/v1/auth/signup').send({
      email: 'mallory@example.com',
      password: PASSWORD,
      role: 'admin',
      emailVerifiedAt: new Date().toISOString(),
    });
    expect(res.status).toBe(201);
    expect(res.body.user).toMatchObject({ role: 'user', emailVerified: false });
  });
});

describe('login and lockout', () => {
  let t;
  beforeAll(async () => {
    t = await createTestApp();
    await signUp(t.app, { email: 'grace@example.com' });
  });
  afterAll(() => t.close());

  const login = (body) => t.api().post('/v1/auth/login').send(body);

  test('returns the user and a session for correct credentials', async () => {
    const res = await login({ email: 'Grace@Example.com', password: PASSWORD });
    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe('grace@example.com');
    expect(res.body.accessToken).toEqual(expect.any(String));
  });

  test('wrong password and unknown email give the same answer', async () => {
    const wrong = await login({ email: 'grace@example.com', password: 'not the password' });
    const unknown = await login({ email: 'nobody@example.com', password: PASSWORD });
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body).toEqual(unknown.body);
  });

  test('locks the account after repeated failures, even for the right password', async () => {
    await signUp(t.app, { email: 'target@example.com' });
    for (let i = 0; i < MAX_FAILED_LOGINS; i += 1) {

      await login({ email: 'target@example.com', password: 'guess' });
    }
    const locked = await login({ email: 'target@example.com', password: PASSWORD });
    expect(locked.status).toBe(429);
    expect(locked.body.error.code).toBe('account_locked');
    expect(Number(locked.headers['retry-after'])).toBeGreaterThan(0);
  });

  test('the lock expires and a successful login clears the counter', async () => {
    const user = await t.ctx.models.User.findOne({ where: { email: 'target@example.com' } });
    await user.update({ lockedUntil: new Date(Date.now() - 1000), failedLoginCount: 3 });
    const res = await login({ email: 'target@example.com', password: PASSWORD });
    expect(res.status).toBe(200);
    await user.reload();
    expect(user.failedLoginCount).toBe(0);
    expect(user.lockedUntil).toBeNull();
  });

  test('a user without a password (social sign-in only) cannot log in with one', async () => {
    await t.ctx.models.User.create({ email: 'social@example.com', passwordHash: null });
    const res = await login({ email: 'social@example.com', password: PASSWORD });
    expect(res.status).toBe(401);
  });
});

describe('refresh and logout', () => {
  let t;
  beforeAll(async () => {
    t = await createTestApp();
  });
  afterAll(() => t.close());

  const refresh = (refreshToken) => t.api().post('/v1/auth/refresh').send({ refreshToken });

  test('rotates the refresh token on every use', async () => {
    const first = await signUp(t.app, { email: 'rotate@example.com' });
    const res = await refresh(first.refreshToken);
    expect(res.status).toBe(200);
    expect(res.body.refreshToken).not.toBe(first.refreshToken);
    expect(res.body.user.email).toBe('rotate@example.com');
    const again = await refresh(res.body.refreshToken);
    expect(again.status).toBe(200);
  });

  test('reusing a rotated token revokes the whole chain', async () => {
    const first = await signUp(t.app, { email: 'stolen@example.com' });
    const second = (await refresh(first.refreshToken)).body;

    const replay = await refresh(first.refreshToken);
    expect(replay.status).toBe(401);
    expect(replay.body.error.code).toBe('invalid_refresh_token');

    // The legitimate holder's newer token is gone too, so the thief gains nothing.
    expect((await refresh(second.refreshToken)).status).toBe(401);
  });

  test('two concurrent refreshes with one token cannot both succeed', async () => {
    const { refreshToken } = await signUp(t.app, { email: 'race@example.com' });
    const results = await Promise.all([refresh(refreshToken), refresh(refreshToken)]);
    expect(results.filter((r) => r.status === 200).length).toBeLessThanOrEqual(1);
  });

  test('stores only a hash of the refresh token', async () => {
    const { refreshToken, user } = await signUp(t.app, { email: 'hash@example.com' });
    const rows = await t.ctx.models.RefreshToken.findAll({ where: { userId: user.id } });
    expect(rows).toHaveLength(1);
    expect(rows[0].tokenHash).toMatch(/^[a-f0-9]{64}$/);
    expect(rows[0].tokenHash).not.toContain(refreshToken.slice(3));
  });

  test('expired refresh tokens are rejected', async () => {
    const { refreshToken, user } = await signUp(t.app, { email: 'old@example.com' });
    await t.ctx.models.RefreshToken.update({ expiresAt: new Date(Date.now() - 1000) }, { where: { userId: user.id } });
    expect((await refresh(refreshToken)).status).toBe(401);
  });

  test.each(['', 'garbage', 'rt_doesnotexist'])('rejects a bad refresh token %p', async (token) => {
    const res = await refresh(token);
    expect([400, 401]).toContain(res.status);
  });

  test('logout ends the session and is always 204', async () => {
    const { refreshToken } = await signUp(t.app, { email: 'bye@example.com' });
    const res = await t.api().post('/v1/auth/logout').send({ refreshToken });
    expect(res.status).toBe(204);
    expect((await refresh(refreshToken)).status).toBe(401);
    expect((await t.api().post('/v1/auth/logout').send({ refreshToken: 'rt_unknown' })).status).toBe(204);
  });

  test('logout leaves the user signed in on other devices', async () => {
    const phone = await signUp(t.app, { email: 'devices@example.com' });
    const laptop = (await t.api().post('/v1/auth/login').send({ email: 'devices@example.com', password: PASSWORD }))
      .body;
    await t.api().post('/v1/auth/logout').send({ refreshToken: phone.refreshToken });
    expect((await refresh(laptop.refreshToken)).status).toBe(200);
  });
});

describe('when email verification is required', () => {
  let t;
  beforeAll(async () => {
    t = await createTestApp({ REQUIRE_EMAIL_VERIFICATION: 'true' });
  });
  afterAll(() => t.close());

  test('sign-up returns no session until the email is confirmed', async () => {
    const res = await t.api().post('/v1/auth/signup').send({ email: 'verify@example.com', password: PASSWORD });
    expect(res.status).toBe(201);
    expect(res.body.verificationRequired).toBe(true);
    expect(res.body.accessToken).toBeUndefined();
  });

  test('login is refused with a clear code until then', async () => {
    const res = await t.api().post('/v1/auth/login').send({ email: 'verify@example.com', password: PASSWORD });
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('email_not_verified');
  });

  test('a wrong password still gets the generic error, so the flag leaks nothing', async () => {
    const res = await t.api().post('/v1/auth/login').send({ email: 'verify@example.com', password: 'wrong pass' });
    expect(res.status).toBe(401);
  });
});

describe('webhooks', () => {
  test('sign-up emits a signed user.created event', async () => {
    const calls = [];
    const fetchImpl = async (url, init) => {
      calls.push({ url, init });
      return { ok: true, status: 200 };
    };
    const t = await createTestApp(
      { WEBHOOK_URL: 'https://hooks.example.com/auth', WEBHOOK_SECRET: 'a-very-long-webhook-secret-123' },
      { fetchImpl },
    );
    await signUp(t.app, { email: 'hook@example.com' });
    await t.ctx.services.webhooks.flush();
    await t.close();

    expect(calls).toHaveLength(1);
    const body = JSON.parse(calls[0].init.body);
    expect(body).toMatchObject({ type: 'user.created', data: { user: { email: 'hook@example.com' } } });
    expect(body.data.user.passwordHash).toBeUndefined();
    expect(calls[0].init.headers['webhook-signature']).toMatch(/^t=\d+,v1=[a-f0-9]{64}$/);
  });
});
