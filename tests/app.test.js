import request from 'supertest';
import app from '../src/app';

describe('GET /pub/PING', () => {
  test('answers PONG', async () => {
    const res = await request(app).get('/pub/PING');
    expect(res.status).toBe(200);
    expect(res.text).toBe('PONG');
  });
});

describe('unknown routes', () => {
  test('return a JSON 404', async () => {
    const res = await request(app).get('/does-not-exist');
    expect(res.status).toBe(404);
    expect(res.body).toMatchObject({ code: 404, success: false, data: null });
  });
});

describe('malformed requests', () => {
  test('a broken JSON body gets a 400, not a 500', async () => {
    const res = await request(app)
      .post('/pub/user/register')
      .set('Content-Type', 'application/json')
      .send('{"email":');
    expect(res.status).toBe(400);
    expect(res.body.errorMessage).toMatch(/JSON/);
  });
});
