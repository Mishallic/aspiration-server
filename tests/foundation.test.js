import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import express from 'express';
import request from 'supertest';
import { SignJWT, generateKeyPair } from 'jose';
import { loadConfig } from '../src/config.js';
import { requireAuth } from '../src/middleware/auth.js';
import { createErrorHandler } from '../src/middleware/errors.js';
import { bearer, createTestApp, signUp } from './helpers.js';

describe('config', () => {
  test('defaults work with no environment at all', () => {
    const config = loadConfig({});
    expect(config.port).toBe(8080);
    expect(config.databaseUrl).toBe('sqlite:./data/auth.sqlite');
    expect(config.jwt.accessTokenTtlSeconds).toBe(900);
    expect(config.oauth.google).toBeNull();
  });

  test.each([
    [{ NODE_ENV: 'production', PUBLIC_URL: 'http://auth.example.com' }, /https in production/],
    [{ GOOGLE_CLIENT_ID: 'id-only' }, /GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET/],
    [{ GITHUB_CLIENT_SECRET: 'secret-only' }, /GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET/],
    [{ WEBHOOK_URL: 'https://hooks.example.com/x' }, /WEBHOOK_SECRET/],
    [{ WEBHOOK_URL: 'https://hooks.example.com/x', WEBHOOK_SECRET: 'short' }, /WEBHOOK_SECRET/],
    [{ ALLOWED_REDIRECT_URLS: 'not a url' }, /ALLOWED_REDIRECT_URLS/],
    [{ PORT: 'eighty' }, /PORT/],
    [{ ACCESS_TOKEN_TTL_SECONDS: '5' }, /ACCESS_TOKEN_TTL_SECONDS/],
  ])('rejects unsafe or broken config %o', (env, message) => {
    expect(() => loadConfig(env)).toThrow(message);
  });

  test('production on localhost over http is allowed for local trials', () => {
    expect(() => loadConfig({ NODE_ENV: 'production', PUBLIC_URL: 'http://localhost:8080' })).not.toThrow();
  });

  test('cookies are secure exactly when the public URL is https', () => {
    expect(loadConfig({ PUBLIC_URL: 'https://auth.example.com' }).secureCookies).toBe(true);
    expect(loadConfig({}).secureCookies).toBe(false);
  });
});

describe('server basics', () => {
  let t;
  beforeAll(async () => {
    t = await createTestApp();
  });
  afterAll(() => t.close());

  test('health check reports ok', async () => {
    const res = await t.api().get('/health');
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: 'ok' });
  });

  test('publishes one RS256 signing key without private parts', async () => {
    const res = await t.api().get('/.well-known/jwks.json');
    expect(res.status).toBe(200);
    expect(res.body.keys).toHaveLength(1);
    const [key] = res.body.keys;
    expect(key).toMatchObject({ kty: 'RSA', alg: 'RS256', use: 'sig' });
    expect(key.kid).toEqual(expect.any(String));
    for (const secret of ['d', 'p', 'q', 'dp', 'dq', 'qi']) expect(key[secret]).toBeUndefined();
  });

  test('discovery document points at the key set', async () => {
    const res = await t.api().get('/.well-known/openid-configuration');
    expect(res.body.issuer).toBe(t.config.jwt.issuer);
    expect(res.body.jwks_uri).toBe(`${t.config.publicUrl}/.well-known/jwks.json`);
  });

  test('the signing key survives a restart because it lives in the database', async () => {
    const before = t.ctx.services.keys.signingKid();
    await t.ctx.services.keys.load();
    expect(t.ctx.services.keys.signingKid()).toBe(before);
  });

  test('unknown routes return the standard error shape', async () => {
    const res = await t.api().get('/nope');
    expect(res.status).toBe(404);
    expect(res.body).toEqual({ error: { code: 'not_found', message: expect.any(String) } });
  });

  test('malformed JSON is a 400, not a 500', async () => {
    const res = await t.api().post('/v1/auth/login').set('Content-Type', 'application/json').send('{"email":');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('invalid_json');
  });

  test('oversized bodies are rejected', async () => {
    const res = await t.api().post('/v1/auth/login').send({ email: 'a@b.co', password: 'x'.repeat(30_000) });
    expect(res.status).toBe(413);
  });

  test('sets security headers and hides the framework', async () => {
    const res = await t.api().get('/health');
    expect(res.headers['x-powered-by']).toBeUndefined();
    expect(res.headers['x-content-type-options']).toBe('nosniff');
    expect(res.headers['strict-transport-security']).toBeDefined();
    expect(res.headers['content-security-policy']).toBeDefined();
  });

  test('API responses are never cached', async () => {
    const res = await t.api().post('/v1/auth/login').send({});
    expect(res.headers['cache-control']).toBe('no-store');
  });
});

describe('requireAuth', () => {
  let t;
  let protectedApp;
  beforeAll(async () => {
    t = await createTestApp();
    protectedApp = express();
    protectedApp.get('/protected', requireAuth(t.ctx), (req, res) => res.json({ id: req.user.id }));
    protectedApp.use(createErrorHandler({ error() {} }));
  });
  afterAll(() => t.close());

  const call = (headers = {}) => request(protectedApp).get('/protected').set(headers);

  test('accepts a valid access token and loads the user', async () => {
    const { user, accessToken } = await signUp(t.app, { email: 'auth@example.com' });
    const res = await call(bearer(accessToken));
    expect(res.status).toBe(200);
    expect(res.body.id).toBe(user.id);
  });

  test.each([
    [{}, 'missing_token'],
    [{ Authorization: 'Basic abc' }, 'missing_token'],
    [{ Authorization: 'Bearer not.a.jwt' }, 'invalid_token'],
  ])('rejects %o with %s', async (headers, code) => {
    const res = await call(headers);
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe(code);
  });

  test('rejects a token signed by a different key', async () => {
    const { user } = await signUp(t.app, { email: 'forged@example.com' });
    const { privateKey } = await generateKeyPair('RS256');
    const forged = await new SignJWT({ role: 'admin' })
      .setProtectedHeader({ alg: 'RS256', kid: t.ctx.services.keys.signingKid() })
      .setIssuer(t.config.jwt.issuer)
      .setAudience(t.config.jwt.audience)
      .setSubject(user.id)
      .setIssuedAt()
      .setExpirationTime('5m')
      .sign(privateKey);
    const res = await call(bearer(forged));
    expect(res.status).toBe(401);
  });

  test('rejects an unsigned token (alg none)', async () => {
    const { user } = await signUp(t.app, { email: 'none@example.com' });
    const encode = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
    const now = Math.floor(Date.now() / 1000);
    const unsigned = `${encode({ alg: 'none', typ: 'JWT' })}.${encode({
      sub: user.id,
      iss: t.config.jwt.issuer,
      aud: t.config.jwt.audience,
      iat: now,
      exp: now + 300,
    })}.`;
    const res = await call(bearer(unsigned));
    expect(res.status).toBe(401);
  });

  test('rejects a token whose user was deleted', async () => {
    const { user, accessToken } = await signUp(t.app, { email: 'gone@example.com' });
    await t.ctx.models.User.destroy({ where: { id: user.id } });
    const res = await call(bearer(accessToken));
    expect(res.status).toBe(401);
  });

  test('rejects tokens issued before sign-out everywhere', async () => {
    const { user, accessToken } = await signUp(t.app, { email: 'revoked@example.com' });
    await new Promise((resolve) => setTimeout(resolve, 1100));
    await t.ctx.services.sessions.revokeAllSessions(user.id);
    const res = await call(bearer(accessToken));
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('token_revoked');
  });
});
