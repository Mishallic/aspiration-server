import request from 'supertest';
import app from '../src/app';
import { sequelize, User } from '../src/models';
import { hashPassword, signToken } from '../src/helpers';

let adminToken;
let userToken;

const allUsers = (token, query = '') =>
  request(app).get(`/api/admin/allUsers${query}`).set('x-token', token);

beforeAll(async () => {
  await sequelize.sync({ force: true });
  const password = await hashPassword('irrelevant-here');

  const admin = await User.create({ email: 'admin@example.com', password, isAdmin: true });
  const user = await User.create({ email: 'user@example.com', password });
  for (let i = 0; i < 23; i += 1) {
    // eslint-disable-next-line no-await-in-loop
    await User.create({ email: `member${i}@example.com`, password });
  }

  adminToken = signToken(admin);
  userToken = signToken(user);
});

afterAll(async () => {
  await sequelize.close();
});

describe('GET /api/admin/allUsers', () => {
  test('returns 401 without a token', async () => {
    const res = await request(app).get('/api/admin/allUsers');
    expect(res.status).toBe(401);
  });

  test('returns 403 for a signed-in non-admin', async () => {
    const res = await allUsers(userToken);
    expect(res.status).toBe(403);
    expect(res.body.success).toBe(false);
  });

  test('lists users for an admin with pagination metadata', async () => {
    const res = await allUsers(adminToken);
    expect(res.status).toBe(200);
    expect(res.body.data).toMatchObject({ page: 1, limit: 20, total: 25, totalPages: 2 });
    expect(res.body.data.users).toHaveLength(20);
  });

  test('never exposes password hashes or verify tokens', async () => {
    const res = await allUsers(adminToken);
    res.body.data.users.forEach((user) => {
      expect(user.password).toBeUndefined();
      expect(user.verifyToken).toBeUndefined();
    });
  });

  test('honours ?page and ?limit, which the original route ignored', async () => {
    const page1 = await allUsers(adminToken, '?page=1&limit=10');
    const page3 = await allUsers(adminToken, '?page=3&limit=10');
    expect(page1.body.data.users).toHaveLength(10);
    expect(page3.body.data.users).toHaveLength(5);
    expect(page3.body.data.totalPages).toBe(3);

    const ids1 = page1.body.data.users.map((u) => u.id);
    const ids3 = page3.body.data.users.map((u) => u.id);
    expect(ids1.filter((id) => ids3.includes(id))).toEqual([]);
  });

  test('caps the page size and falls back on bad input', async () => {
    const huge = await allUsers(adminToken, '?limit=5000');
    expect(huge.body.data.limit).toBe(100);
    const junk = await allUsers(adminToken, '?page=-4&limit=abc');
    expect(junk.body.data).toMatchObject({ page: 1, limit: 20 });
  });
});
