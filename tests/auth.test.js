import request from 'supertest';
import jwt from 'jsonwebtoken';
import app from '../src/app';
import { sequelize, User } from '../src/models';
import config from '../src/config';

const EMAIL = 'ada@example.com';
const PASSWORD = 'analytical-engine';

const register = (body) => request(app).post('/pub/user/register').send(body);
const login = (body) => request(app).post('/pub/user/login').send(body);

beforeAll(async () => {
  await sequelize.sync({ force: true });
});

afterAll(async () => {
  await sequelize.close();
});

describe('POST /pub/user/register', () => {
  test('creates a user and never returns secrets', async () => {
    const res = await register({ email: EMAIL, password: PASSWORD, firstName: 'Ada' });
    expect(res.status).toBe(201);
    expect(res.body.success).toBe(true);
    expect(res.body.data.user).toMatchObject({ email: EMAIL, firstName: 'Ada', isVerified: false });
    expect(res.body.data.user.password).toBeUndefined();
    expect(res.body.data.user.verifyToken).toBeUndefined();
  });

  test('stores a bcrypt hash, not the password or an MD5', async () => {
    const user = await User.scope('withSecretColumns').findOne({ where: { email: EMAIL } });
    expect(user.password).toMatch(/^\$2[aby]\$/);
    expect(user.password).not.toMatch(/^[a-f0-9]{32}$/);
  });

  test('rejects a duplicate email regardless of case', async () => {
    const res = await register({ email: 'ADA@Example.com', password: PASSWORD });
    expect(res.status).toBe(409);
    expect(res.body.success).toBe(false);
  });

  test.each([
    [{}, 'missing both'],
    [{ email: 'x@y.co' }, 'missing password'],
    [{ password: PASSWORD }, 'missing email'],
    [{ email: '   ', password: PASSWORD }, 'blank email'],
    [{ email: 'not-an-email', password: PASSWORD }, 'invalid email'],
    [{ email: 'x@y.co', password: 'short' }, 'short password'],
  ])('returns 400 for %p (%s)', async (body) => {
    const res = await register(body);
    expect(res.status).toBe(400);
    expect(res.body.errorMessage).toEqual(expect.any(String));
  });

  test('ignores attempts to self-assign admin or verified status', async () => {
    const res = await register({ email: 'mallory@example.com', password: PASSWORD, isAdmin: true, isVerified: true });
    expect(res.status).toBe(201);
    const user = await User.scope('withSecretColumns').findOne({ where: { email: 'mallory@example.com' } });
    expect(user.isAdmin).toBe(false);
    expect(user.isVerified).toBe(false);
  });
});

describe('POST /pub/user/login', () => {
  test('returns a token and the user for correct credentials', async () => {
    const res = await login({ email: EMAIL, password: PASSWORD });
    expect(res.status).toBe(200);
    expect(res.body.data.user.email).toBe(EMAIL);
    expect(res.body.data.user.password).toBeUndefined();
    const decoded = jwt.verify(res.body.data.token, config.jwtSecret);
    expect(decoded.user.email).toBe(EMAIL);
  });

  test('accepts the email in any case', async () => {
    const res = await login({ email: 'Ada@EXAMPLE.com', password: PASSWORD });
    expect(res.status).toBe(200);
  });

  test('wrong password and unknown email give the same 401', async () => {
    const wrong = await login({ email: EMAIL, password: 'not-the-password' });
    const unknown = await login({ email: 'nobody@example.com', password: PASSWORD });
    expect(wrong.status).toBe(401);
    expect(unknown.status).toBe(401);
    expect(wrong.body.errorMessage).toEqual(unknown.body.errorMessage);
  });

  test('returns 400 when fields are missing', async () => {
    const res = await login({ email: EMAIL });
    expect(res.status).toBe(400);
  });
});

describe('authenticated routes', () => {
  let token;

  beforeAll(async () => {
    const res = await login({ email: EMAIL, password: PASSWORD });
    token = res.body.data.token;
  });

  describe('GET /api/me', () => {
    test('returns the signed-in user', async () => {
      const res = await request(app).get('/api/me').set('x-token', token);
      expect(res.status).toBe(200);
      expect(res.body.data.user.email).toBe(EMAIL);
      expect(res.body.data.user.password).toBeUndefined();
    });

    test('returns 401 without a token', async () => {
      const res = await request(app).get('/api/me');
      expect(res.status).toBe(401);
    });

    test('returns 401 for a forged token', async () => {
      const forged = jwt.sign({ user: { userId: 1, email: EMAIL } }, 'attacker-secret');
      const res = await request(app).get('/api/me').set('x-token', forged);
      expect(res.status).toBe(401);
    });

    test('returns 401 for an expired token', async () => {
      const expired = jwt.sign({ user: { userId: 1, email: EMAIL } }, config.jwtSecret, { expiresIn: -10 });
      const res = await request(app).get('/api/me').set('x-token', expired);
      expect(res.status).toBe(401);
    });

    test('the old unauthenticated token-minting endpoint is gone', async () => {
      const res = await request(app).post('/pub/user/me').send({ id: 1 });
      expect(res.status).toBe(404);
      expect(res.body.data).toBeNull();
    });
  });

  describe('POST /api/changePassword', () => {
    const NEW_PASSWORD = 'difference-engine';

    test('returns 401 without a token', async () => {
      const res = await request(app)
        .post('/api/changePassword')
        .send({ oldPassword: PASSWORD, newPassword: NEW_PASSWORD });
      expect(res.status).toBe(401);
    });

    test('returns 400 when fields are missing', async () => {
      const res = await request(app).post('/api/changePassword').set('x-token', token).send({});
      expect(res.status).toBe(400);
    });

    test('returns 400 for a short new password', async () => {
      const res = await request(app)
        .post('/api/changePassword')
        .set('x-token', token)
        .send({ oldPassword: PASSWORD, newPassword: 'short' });
      expect(res.status).toBe(400);
    });

    test('returns 401 when the old password is wrong', async () => {
      const res = await request(app)
        .post('/api/changePassword')
        .set('x-token', token)
        .send({ oldPassword: 'not-the-password', newPassword: NEW_PASSWORD });
      expect(res.status).toBe(401);
    });

    test('changes the password so only the new one logs in', async () => {
      const res = await request(app)
        .post('/api/changePassword')
        .set('x-token', token)
        .send({ oldPassword: PASSWORD, newPassword: NEW_PASSWORD });
      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);

      expect((await login({ email: EMAIL, password: PASSWORD })).status).toBe(401);
      expect((await login({ email: EMAIL, password: NEW_PASSWORD })).status).toBe(200);
    });
  });

  test('a token for a deleted user is rejected', async () => {
    await register({ email: 'temp@example.com', password: PASSWORD });
    const { body } = await login({ email: 'temp@example.com', password: PASSWORD });
    await User.destroy({ where: { email: 'temp@example.com' } });
    const res = await request(app).get('/api/me').set('x-token', body.data.token);
    expect(res.status).toBe(401);
  });
});
