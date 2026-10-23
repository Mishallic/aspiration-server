import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { PASSWORD, bearer, createTestApp, signUp } from './helpers.js';

describe('account (me) routes', () => {
  let t;
  beforeAll(async () => {
    t = await createTestApp();
  });
  afterAll(() => t.close());

  const asUser = async (email) => {
    const { accessToken, refreshToken, user } = await signUp(t.app, { email });
    return { auth: bearer(accessToken), refreshToken, user };
  };

  test('GET /me returns the current user, no secrets', async () => {
    const { auth } = await asUser('me1@example.com');
    const res = await t.api().get('/v1/me').set(auth);
    expect(res.status).toBe(200);
    expect(res.body.user.email).toBe('me1@example.com');
    expect(res.body.user.passwordHash).toBeUndefined();
  });

  test('GET /me needs a token', async () => {
    expect((await t.api().get('/v1/me')).status).toBe(401);
  });

  test('PATCH /me updates the profile and rejects empty or bad input', async () => {
    const { auth } = await asUser('me2@example.com');
    const ok = await t.api().patch('/v1/me').set(auth).send({ firstName: 'Grace', lastName: 'Hopper' });
    expect(ok.status).toBe(200);
    expect(ok.body.user).toMatchObject({ firstName: 'Grace', lastName: 'Hopper' });

    expect((await t.api().patch('/v1/me').set(auth).send({})).status).toBe(400);
    expect((await t.api().patch('/v1/me').set(auth).send({ avatarUrl: 'not-a-url' })).status).toBe(400);
  });

  test('PATCH /me cannot change role or email', async () => {
    const { auth, user } = await asUser('me3@example.com');
    const res = await t.api().patch('/v1/me').set(auth).send({ role: 'admin', email: 'new@example.com', firstName: 'X' });
    expect(res.status).toBe(200);
    expect(res.body.user).toMatchObject({ role: 'user', email: 'me3@example.com' });
    const fresh = await t.ctx.models.User.findByPk(user.id);
    expect(fresh.role).toBe('user');
  });

  test('change-password requires the correct current password and rotates sessions', async () => {
    const { auth, refreshToken } = await asUser('me4@example.com');

    expect((await t.api().post('/v1/me/change-password').set(auth).send({ newPassword: 'brand new pass' })).status).toBe(400);
    expect(
      (await t.api().post('/v1/me/change-password').set(auth).send({ currentPassword: 'wrong', newPassword: 'brand new pass' })).status,
    ).toBe(401);

    const ok = await t
      .api()
      .post('/v1/me/change-password')
      .set(auth)
      .send({ currentPassword: PASSWORD, newPassword: 'brand new pass' });
    expect(ok.status).toBe(200);
    expect(ok.body.accessToken).toEqual(expect.any(String));

    // Old refresh token is dead; the new password works.
    expect((await t.api().post('/v1/auth/refresh').send({ refreshToken })).status).toBe(401);
    expect((await t.api().post('/v1/auth/login').send({ email: 'me4@example.com', password: 'brand new pass' })).status).toBe(200);
  });

  test('sessions list reflects logins and logout-all clears them', async () => {
    const { auth, user } = await asUser('me5@example.com');
    await t.api().post('/v1/auth/login').send({ email: 'me5@example.com', password: PASSWORD });

    const list = await t.api().get('/v1/me/sessions').set(auth);
    expect(list.status).toBe(200);
    expect(list.body.sessions.length).toBeGreaterThanOrEqual(2);

    expect((await t.api().post('/v1/me/logout-all').set(auth)).status).toBe(204);
    // Only this user's sessions are cleared; other users are untouched.
    const mine = await t.ctx.models.RefreshToken.count({ where: { userId: user.id, revokedAt: null } });
    expect(mine).toBe(0);
  });

  test('DELETE /me removes the account and cascades', async () => {
    const { auth, user } = await asUser('me6@example.com');
    expect((await t.api().delete('/v1/me').set(auth)).status).toBe(204);
    expect(await t.ctx.models.User.findByPk(user.id)).toBeNull();
    expect(await t.ctx.models.RefreshToken.count({ where: { userId: user.id } })).toBe(0);
    // The access token no longer resolves to a user.
    expect((await t.api().get('/v1/me').set(auth)).status).toBe(401);
  });
});

describe('admin routes', () => {
  let t;
  let adminAuth;
  beforeAll(async () => {
    t = await createTestApp();
    const { user } = await signUp(t.app, { email: 'admin@example.com' });
    await t.ctx.models.User.update({ role: 'admin' }, { where: { id: user.id } });
    // Re-login so the token carries the admin role (role change revokes old sessions).
    const res = await t.api().post('/v1/auth/login').send({ email: 'admin@example.com', password: PASSWORD });
    adminAuth = bearer(res.body.accessToken);
    for (let i = 0; i < 5; i += 1) await signUp(t.app, { email: `u${i}@example.com` });
  });
  afterAll(() => t.close());

  test('non-admins are forbidden', async () => {
    const { accessToken } = await signUp(t.app, { email: 'plain@example.com' });
    const res = await t.api().get('/v1/admin/users').set(bearer(accessToken));
    expect(res.status).toBe(403);
    expect(res.body.error.code).toBe('admin_required');
  });

  test('lists and paginates users', async () => {
    const res = await t.api().get('/v1/admin/users?limit=3').set(adminAuth);
    expect(res.status).toBe(200);
    expect(res.body.users).toHaveLength(3);
    expect(res.body.total).toBeGreaterThanOrEqual(6);
    expect(res.body.users[0].passwordHash).toBeUndefined();
  });

  test('searches by email', async () => {
    const res = await t.api().get('/v1/admin/users?search=u3@').set(adminAuth);
    expect(res.body.users.map((u) => u.email)).toContain('u3@example.com');
  });

  test('changes a role, which revokes that user\'s sessions', async () => {
    const { user, refreshToken } = await signUp(t.app, { email: 'promote@example.com' });
    const res = await t.api().patch(`/v1/admin/users/${user.id}/role`).set(adminAuth).send({ role: 'admin' });
    expect(res.status).toBe(200);
    expect(res.body.user.role).toBe('admin');
    expect((await t.api().post('/v1/auth/refresh').send({ refreshToken })).status).toBe(401);
  });

  test('deletes another user but not oneself here', async () => {
    const { user } = await signUp(t.app, { email: 'victim@example.com' });
    expect((await t.api().delete(`/v1/admin/users/${user.id}`).set(adminAuth)).status).toBe(204);
    expect(await t.ctx.models.User.findByPk(user.id)).toBeNull();

    const admin = await t.ctx.models.User.findOne({ where: { email: 'admin@example.com' } });
    const self = await t.api().delete(`/v1/admin/users/${admin.id}`).set(adminAuth);
    expect(self.status).toBe(403);
  });

  test('404 for unknown user id', async () => {
    const res = await t.api().get('/v1/admin/users/00000000-0000-0000-0000-000000000000').set(adminAuth);
    expect(res.status).toBe(404);
  });
});
