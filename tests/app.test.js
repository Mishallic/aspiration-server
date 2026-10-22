import request from 'supertest';
import app from '../src/app';

describe('GET /pub/PING', () => {
  test('answers PONG', async () => {
    const res = await request(app).get('/pub/PING');
    expect(res.status).toBe(200);
    expect(res.text).toBe('PONG');
  });
});
