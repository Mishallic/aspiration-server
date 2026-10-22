import request from 'supertest';
import app from '../src/app';
import { sequelize, User } from '../src/models';
import { findOrCreateGoogleUser } from '../src/controllers/user/user.controller';
import { comparePassword, hashPassword } from '../src/helpers';

const googleProfile = (overrides = {}) => ({
  id: 'google-123',
  name: { givenName: 'Grace', familyName: 'Hopper' },
  emails: [{ value: 'Grace@Example.com' }],
  photos: [{ value: 'https://example.com/grace.png' }],
  ...overrides,
});

beforeAll(async () => {
  await sequelize.sync({ force: true });
});

afterAll(async () => {
  await sequelize.close();
});

describe('findOrCreateGoogleUser', () => {
  test('creates a verified user from a Google profile', async () => {
    const user = await findOrCreateGoogleUser(googleProfile());
    expect(user).toMatchObject({
      email: 'grace@example.com',
      firstName: 'Grace',
      lastName: 'Hopper',
      googleId: 'google-123',
      isVerified: true,
      profilePhoto: 'https://example.com/grace.png',
    });
  });

  test('returns the same user on the next sign-in instead of duplicating', async () => {
    const again = await findOrCreateGoogleUser(googleProfile());
    const first = await User.findOne({ where: { googleId: 'google-123' } });
    expect(again.id).toBe(first.id);
    expect(await User.count({ where: { email: 'grace@example.com' } })).toBe(1);
  });

  test('gives Google users an unguessable bcrypt password', async () => {
    const user = await User.scope('withSecretColumns').findOne({ where: { googleId: 'google-123' } });
    expect(user.password).toMatch(/^\$2[aby]\$/);
    await expect(comparePassword('', user.password)).resolves.toBe(false);
  });

  test('links Google to an existing email/password account', async () => {
    const existing = await User.create({ email: 'linus@example.com', password: await hashPassword('password123') });
    const linked = await findOrCreateGoogleUser(googleProfile({ id: 'google-456', emails: [{ value: 'linus@example.com' }] }));
    expect(linked.id).toBe(existing.id);
    expect(linked.googleId).toBe('google-456');
    expect(linked.isVerified).toBe(true);
  });

  test('refuses a profile with no email', async () => {
    await expect(findOrCreateGoogleUser(googleProfile({ id: 'google-789', emails: [] }))).rejects.toThrow(/email/);
  });
});

describe('Google routes without credentials configured', () => {
  test.each(['/oauth/google', '/oauth/google/callback'])('%s returns 503', async (path) => {
    const res = await request(app).get(path);
    expect(res.status).toBe(503);
    expect(res.body.success).toBe(false);
  });

  test('the failure route reports a 401', async () => {
    const res = await request(app).get('/oauth/google/failure');
    expect(res.status).toBe(401);
  });
});
