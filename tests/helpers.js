import request from 'supertest';
import { createLocalJWKSet, jwtVerify } from 'jose';
import { loadConfig } from '../src/config.js';
import { createContext } from '../src/context.js';
import { createApp } from '../src/app.js';

const silentLogger = { info() {}, warn() {}, error() {}, log() {} };

// A fresh app with its own in-memory database. Pass env overrides to change config,
// and `fetchImpl` to stub outbound HTTP (webhooks, OAuth providers).
export async function createTestApp(env = {}, { fetchImpl, logger = silentLogger } = {}) {
  const config = loadConfig({ NODE_ENV: 'test', RATE_LIMIT_ENABLED: 'false', ...env });
  const ctx = await createContext(config, { logger, fetchImpl });
  const app = createApp(ctx);
  return { app, ctx, config, api: () => request(app), close: () => ctx.close() };
}

export const PASSWORD = 'correct horse battery';

export async function signUp(app, { email = 'ada@example.com', password = PASSWORD, ...rest } = {}) {
  const res = await request(app).post('/v1/auth/signup').send({ email, password, ...rest });
  if (res.status !== 201) throw new Error(`signup failed: ${res.status} ${JSON.stringify(res.body)}`);
  return res.body;
}

export const bearer = (token) => ({ Authorization: `Bearer ${token}` });

// Verifies a token exactly as a third-party backend would: only the public JWKS.
export async function verifyLikeAThirdParty(app, token, config) {
  const { body: jwks } = await request(app).get('/.well-known/jwks.json');
  const { payload, protectedHeader } = await jwtVerify(token, createLocalJWKSet(jwks), {
    issuer: config.jwt.issuer,
    audience: config.jwt.audience,
  });
  return { payload, protectedHeader };
}

export const lastEmail = (ctx) => ctx.services.mailer.outbox.at(-1);

export function tokenFromEmail(message) {
  const match = /[?&]token=([A-Za-z0-9_-]+)/.exec(message.text);
  if (!match) throw new Error('No token link in email');
  return match[1];
}
