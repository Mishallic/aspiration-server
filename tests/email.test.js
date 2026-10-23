import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { PASSWORD, createTestApp, lastEmail, signUp, tokenFromEmail } from './helpers.js';

describe('email verification', () => {
  let t;
  beforeAll(async () => {
    t = await createTestApp();
  });
  afterAll(() => t.close());

  test('a signup token verifies the email exactly once', async () => {
    const { user } = await signUp(t.app, { email: 'verify@example.com' });
    const token = tokenFromEmail(lastEmail(t.ctx));

    const res = await t.api().post('/v1/auth/verify-email').send({ token });
    expect(res.status).toBe(200);
    expect(res.body.user.emailVerified).toBe(true);
    const fresh = await t.ctx.models.User.findByPk(user.id);
    expect(fresh.emailVerifiedAt).toBeInstanceOf(Date);

    // Reusing the token fails.
    expect((await t.api().post('/v1/auth/verify-email').send({ token })).status).toBe(400);
  });

  test.each(['', 'x', 'a'.repeat(50)])('rejects a bad token %p', async (token) => {
    const res = await t.api().post('/v1/auth/verify-email').send({ token });
    expect([400]).toContain(res.status);
  });

  test('resend is always 204 and never reveals whether the account exists', async () => {
    await signUp(t.app, { email: 'resend@example.com' });
    const known = await t.api().post('/v1/auth/verify-email/resend').send({ email: 'resend@example.com' });
    const unknown = await t.api().post('/v1/auth/verify-email/resend').send({ email: 'nobody@example.com' });
    expect(known.status).toBe(204);
    expect(unknown.status).toBe(204);
    await t.ctx.background.flush();
    expect(lastEmail(t.ctx).to).toBe('resend@example.com');
  });

  test('the GET verification page confirms the email', async () => {
    await signUp(t.app, { email: 'page@example.com' });
    const token = tokenFromEmail(lastEmail(t.ctx));
    const res = await t.api().get(`/verify-email?token=${token}`);
    expect(res.status).toBe(200);
    expect(res.headers['content-type']).toMatch(/html/);
    expect(res.text).toMatch(/confirmed/i);
    expect(res.headers['content-security-policy']).toMatch(/script-src 'nonce-/);
  });

  test('the verification page shows an error for a bad token', async () => {
    const res = await t.api().get('/verify-email?token=nope');
    expect(res.status).toBe(400);
    expect(res.text).toMatch(/not valid|invalid|expired/i);
  });
});

describe('password reset', () => {
  let t;
  beforeAll(async () => {
    t = await createTestApp();
    await signUp(t.app, { email: 'reset@example.com' });
  });
  afterAll(() => t.close());

  // The email is sent in the background after the 204, so wait for it before reading.
  const forgot = async (email) => {
    const res = await t.api().post('/v1/auth/password/forgot').send({ email });
    await t.ctx.background.flush();
    return res;
  };

  test('forgot is always 204 whether or not the account exists', async () => {
    expect((await forgot('reset@example.com')).status).toBe(204);
    expect((await forgot('ghost@example.com')).status).toBe(204);
  });

  test('a reset link sets a new password, ends sessions, and works once', async () => {
    const before = await t.api().post('/v1/auth/login').send({ email: 'reset@example.com', password: PASSWORD });
    const oldRefresh = before.body.refreshToken;

    await forgot('reset@example.com');
    const token = tokenFromEmail(lastEmail(t.ctx));

    // A weak new password is rejected without spending the token.
    expect((await t.api().post('/v1/auth/password/reset').send({ token, newPassword: 'short' })).status).toBe(400);

    const ok = await t.api().post('/v1/auth/password/reset').send({ token, newPassword: 'a fresh strong password' });
    expect(ok.status).toBe(204);

    // Old sessions are gone; the old password fails; the new one works; token is spent.
    expect((await t.api().post('/v1/auth/refresh').send({ refreshToken: oldRefresh })).status).toBe(401);
    expect((await t.api().post('/v1/auth/login').send({ email: 'reset@example.com', password: PASSWORD })).status).toBe(401);
    expect(
      (await t.api().post('/v1/auth/login').send({ email: 'reset@example.com', password: 'a fresh strong password' })).status,
    ).toBe(200);
    expect(
      (await t.api().post('/v1/auth/password/reset').send({ token, newPassword: 'another strong password' })).status,
    ).toBe(400);
  });

  test('requesting a new reset invalidates the previous link', async () => {
    await forgot('reset@example.com');
    const first = tokenFromEmail(lastEmail(t.ctx));
    await forgot('reset@example.com');
    const second = tokenFromEmail(lastEmail(t.ctx));
    expect(first).not.toBe(second);
    expect((await t.api().post('/v1/auth/password/reset').send({ token: first, newPassword: 'yet another password' })).status).toBe(400);
    expect((await t.api().post('/v1/auth/password/reset').send({ token: second, newPassword: 'yet another password' })).status).toBe(204);
  });

  test('the reset page serves a form with a nonce CSP', async () => {
    const res = await t.api().get('/reset-password?token=abc');
    expect(res.status).toBe(200);
    expect(res.text).toMatch(/new password/i);
    expect(res.headers['content-security-policy']).toMatch(/script-src 'nonce-/);
  });
});
