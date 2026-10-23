import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import request from 'supertest';
import { createTestApp, verifyLikeAThirdParty } from './helpers.js';
import { makeFakeProvider, stubFetch } from './oauthHelpers.js';

const GOOGLE_JWKS = 'https://www.googleapis.com/oauth2/v3/certs';
const APPLE_JWKS = 'https://appleid.apple.com/auth/keys';
const GOOGLE_CLIENT = 'google-client-id.apps.googleusercontent.com';
const GOOGLE_NATIVE = 'ios-client-id.apps.googleusercontent.com';
const APPLE_CLIENT = 'com.example.app';

describe('native OAuth sign-in', () => {
  let t;
  let google;
  let apple;

  beforeAll(async () => {
    google = await makeFakeProvider({ jwksUrl: GOOGLE_JWKS, issuer: 'https://accounts.google.com' });
    apple = await makeFakeProvider({ jwksUrl: APPLE_JWKS, issuer: 'https://appleid.apple.com' });
    const fetchImpl = stubFetch([
      [GOOGLE_JWKS, () => google.jwks],
      [APPLE_JWKS, () => apple.jwks],
    ]);
    t = await createTestApp(
      {
        GOOGLE_CLIENT_ID: GOOGLE_CLIENT,
        GOOGLE_CLIENT_SECRET: 'google-secret',
        GOOGLE_NATIVE_CLIENT_IDS: 'ios-client-id.apps.googleusercontent.com',
        APPLE_CLIENT_IDS: APPLE_CLIENT,
      },
      { fetchImpl },
    );
  });
  afterAll(() => t.close());

  test('lists the configured providers', async () => {
    const res = await t.api().get('/v1/auth/oauth/providers');
    const byName = Object.fromEntries(res.body.providers.map((p) => [p.provider, p]));
    expect(byName.google).toMatchObject({ native: true, web: true });
    expect(byName.apple).toMatchObject({ native: true, web: false });
    expect(byName.github).toBeUndefined();
  });

  test('a valid Google ID token creates a verified user and a real session', async () => {
    const idToken = await google.idToken(
      { sub: 'g-1', email: 'Grace@Gmail.com', email_verified: true, given_name: 'Grace', family_name: 'Hopper' },
      { aud: 'ios-client-id.apps.googleusercontent.com' },
    );
    const res = await t.api().post('/v1/auth/oauth/google/native').send({ idToken });
    expect(res.status).toBe(200);
    expect(res.body.user).toMatchObject({ email: 'grace@gmail.com', emailVerified: true, firstName: 'Grace' });
    expect(res.body.user.hasPassword).toBe(false);

    const { payload } = await verifyLikeAThirdParty(t.app, res.body.accessToken, t.config);
    expect(payload.sub).toBe(res.body.user.id);

    // Signing in again returns the same user, not a duplicate.
    const again = await t.api().post('/v1/auth/oauth/google/native').send({ idToken });
    expect(again.body.user.id).toBe(res.body.user.id);
  });

  test('rejects a Google token for an unknown audience', async () => {
    const idToken = await google.idToken({ sub: 'g-2', email: 'x@gmail.com', email_verified: true }, { aud: 'attacker-app' });
    const res = await t.api().post('/v1/auth/oauth/google/native').send({ idToken });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('invalid_provider_token');
  });

  test('rejects a token signed by the wrong key', async () => {
    const other = await makeFakeProvider({ jwksUrl: GOOGLE_JWKS, issuer: 'https://accounts.google.com' });
    const idToken = await other.idToken({ sub: 'g-3', email: 'y@gmail.com', email_verified: true }, { aud: GOOGLE_CLIENT });
    const res = await t.api().post('/v1/auth/oauth/google/native').send({ idToken });
    expect(res.status).toBe(400);
  });

  test('does NOT accept a token minted for the confidential web client id at the native endpoint', async () => {
    const idToken = await google.idToken(
      { sub: 'g-web', email: 'web-id@gmail.com', email_verified: true },
      { aud: GOOGLE_CLIENT },
    );
    const res = await t.api().post('/v1/auth/oauth/google/native').send({ idToken });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('invalid_provider_token');
  });

  test('when a nonce is supplied it must match the token', async () => {
    const idToken = await google.idToken(
      { sub: 'g-nonce', email: 'nonce@gmail.com', email_verified: true, nonce: 'abc123' },
      { aud: GOOGLE_NATIVE },
    );
    const bad = await t.api().post('/v1/auth/oauth/google/native').send({ idToken, nonce: 'wrong' });
    expect(bad.status).toBe(400);
    const good = await t.api().post('/v1/auth/oauth/google/native').send({ idToken, nonce: 'abc123' });
    expect(good.status).toBe(200);
  });

  test('links a Google login to an existing, verified account', async () => {
    await t.api().post('/v1/auth/signup').send({ email: 'link@example.com', password: 'password-here-ok' });
    // The account has proven control of its email, so auto-linking is safe.
    await t.ctx.models.User.update({ emailVerifiedAt: new Date() }, { where: { email: 'link@example.com' } });
    const idToken = await google.idToken(
      { sub: 'g-link', email: 'link@example.com', email_verified: true },
      { aud: GOOGLE_NATIVE },
    );
    const res = await t.api().post('/v1/auth/oauth/google/native').send({ idToken });
    expect(res.status).toBe(200);
    const user = await t.ctx.models.User.findOne({ where: { email: 'link@example.com' } });
    expect(res.body.user.id).toBe(user.id);
    expect(await t.ctx.models.Identity.count({ where: { userId: user.id } })).toBe(1);
  });

  test('refuses to link into an unverified password account (pre-registration takeover guard)', async () => {
    // Attacker pre-registers the victim's email with a password; account is unverified.
    await t.api().post('/v1/auth/signup').send({ email: 'victim@example.com', password: 'attacker-chosen-pw' });
    const victim = await t.ctx.models.User.findOne({ where: { email: 'victim@example.com' } });
    // Victim later signs in with Google on the same (provider-verified) address.
    const idToken = await google.idToken(
      { sub: 'g-victim', email: 'victim@example.com', email_verified: true },
      { aud: GOOGLE_NATIVE },
    );
    const res = await t.api().post('/v1/auth/oauth/google/native').send({ idToken });
    expect(res.status).toBe(409);
    expect(res.body.error.code).toBe('account_exists');
    // No provider identity was attached to the attacker's pre-registered account.
    expect(await t.ctx.models.Identity.findOne({ where: { userId: victim.id } })).toBeNull();
  });

  test('does NOT link on an unverified provider email, creating a separate account', async () => {
    await t.api().post('/v1/auth/signup').send({ email: 'target@example.com', password: 'password-here-ok' });
    const target = await t.ctx.models.User.findOne({ where: { email: 'target@example.com' } });
    const idToken = await google.idToken(
      { sub: 'attacker-sub', email: 'target@example.com', email_verified: false },
      { aud: GOOGLE_NATIVE },
    );
    const res = await t.api().post('/v1/auth/oauth/google/native').send({ idToken });
    expect(res.status).toBe(200);
    expect(res.body.user.id).not.toBe(target.id);
    expect(await t.ctx.models.Identity.findOne({ where: { userId: target.id } })).toBeNull();
  });

  test('Apple tokens work and tolerate the string email_verified', async () => {
    const idToken = await apple.idToken({ sub: 'a-1', email: 'grace@icloud.com', email_verified: 'true' }, { aud: APPLE_CLIENT });
    const res = await t.api().post('/v1/auth/oauth/apple/native').send({ idToken });
    expect(res.status).toBe(200);
    expect(res.body.user).toMatchObject({ email: 'grace@icloud.com', emailVerified: true });
  });

  test('github has no native endpoint', async () => {
    const res = await t.api().post('/v1/auth/oauth/github/native').send({ idToken: 'x'.repeat(20) });
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('provider_not_configured');
  });

  test('unknown provider is a 404', async () => {
    expect((await t.api().post('/v1/auth/oauth/twitter/native').send({ idToken: 'x'.repeat(20) })).status).toBe(404);
  });
});

describe('web OAuth flow', () => {
  let t;
  let google;
  const REDIRECT = 'https://app.example.com/auth/callback';

  beforeAll(async () => {
    google = await makeFakeProvider({ jwksUrl: GOOGLE_JWKS, issuer: 'https://accounts.google.com' });
    const fetchImpl = stubFetch([
      [GOOGLE_JWKS, () => google.jwks],
      [
        'https://oauth2.googleapis.com/token',
        async () => ({ id_token: await google.idToken({ sub: 'web-1', email: 'web@gmail.com', email_verified: true }, { aud: GOOGLE_CLIENT }) }),
      ],
      ['https://github.com/login/oauth/access_token', () => ({ access_token: 'gh-token' })],
      ['https://api.github.com/user/emails', () => [{ email: 'dev@github.com', primary: true, verified: true }]],
      ['https://api.github.com/user', () => ({ id: 42, name: 'Dev Eloper', avatar_url: 'https://x/y.png' })],
    ]);
    t = await createTestApp(
      {
        GOOGLE_CLIENT_ID: GOOGLE_CLIENT,
        GOOGLE_CLIENT_SECRET: 'google-secret',
        GITHUB_CLIENT_ID: 'gh-client',
        GITHUB_CLIENT_SECRET: 'gh-secret',
        ALLOWED_REDIRECT_URLS: `${REDIRECT},https://other.example.com/cb`,
      },
      { fetchImpl },
    );
  });
  afterAll(() => t.close());

  const parseFragment = (location) => new URLSearchParams(new URL(location).hash.slice(1));

  test('start rejects a redirect_uri that is not allowlisted', async () => {
    const res = await t.api().get('/v1/auth/oauth/google/start?redirect_uri=https://evil.example.com/cb');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('invalid_redirect_uri');
  });

  test('start redirects to Google with a state parameter', async () => {
    const res = await t.api().get(`/v1/auth/oauth/google/start?redirect_uri=${encodeURIComponent(REDIRECT)}`);
    expect(res.status).toBe(302);
    const location = new URL(res.headers.location);
    expect(location.origin + location.pathname).toBe('https://accounts.google.com/o/oauth2/v2/auth');
    expect(location.searchParams.get('state')).toBeTruthy();
    expect(location.searchParams.get('redirect_uri')).toBe(`${t.config.publicUrl}/v1/auth/oauth/google/callback`);
  });

  // A persistent agent so the state cookie set by /start is sent to /callback,
  // mirroring the same browser completing the flow.
  const runFlow = async (provider) => {
    const agent = request.agent(t.app);
    const start = await agent.get(`/v1/auth/oauth/${provider}/start?redirect_uri=${encodeURIComponent(REDIRECT)}`);
    const state = new URL(start.headers.location).searchParams.get('state');
    const callback = await agent.get(`/v1/auth/oauth/${provider}/callback?code=prov-code&state=${state}`);
    expect(callback.status).toBe(302);
    expect(callback.headers.location.startsWith(`${REDIRECT}#`)).toBe(true);
    return { state, code: parseFragment(callback.headers.location).get('code') };
  };

  test('full Google web flow issues an exchangeable one-time code, no tokens in the URL', async () => {
    const { state, code } = await runFlow('google');
    expect(code).toBeTruthy();

    const location = `${REDIRECT}#code=${code}`;
    expect(location).not.toMatch(/access|refresh|eyJ/);

    const exchange = await t.api().post('/v1/auth/oauth/exchange').send({ code });
    expect(exchange.status).toBe(200);
    expect(exchange.body.user.email).toBe('web@gmail.com');
    expect(exchange.body.refreshToken).toMatch(/^rt_/);

    // The app code is single-use, and the state cannot be replayed.
    expect((await t.api().post('/v1/auth/oauth/exchange').send({ code })).status).toBe(400);
    // Replaying the state in a different browser (no matching cookie) is refused.
    expect((await t.api().get(`/v1/auth/oauth/google/callback?code=x&state=${state}`)).status).toBe(400);
  });

  test('a callback with a valid state but no matching cookie is refused (login-CSRF guard)', async () => {
    const start = await t.api().get(`/v1/auth/oauth/google/start?redirect_uri=${encodeURIComponent(REDIRECT)}`);
    const state = new URL(start.headers.location).searchParams.get('state');
    // A fresh client (no oauth_state cookie) cannot complete someone else's flow.
    const res = await t.api().get(`/v1/auth/oauth/google/callback?code=prov-code&state=${state}`);
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('invalid_state');
  });

  test('github web flow reads the verified primary email', async () => {
    const { code } = await runFlow('github');
    const exchange = await t.api().post('/v1/auth/oauth/exchange').send({ code });
    expect(exchange.status).toBe(200);
    expect(exchange.body.user).toMatchObject({ email: 'dev@github.com', emailVerified: true, firstName: 'Dev' });
  });

  test('a tampered or unknown state is refused', async () => {
    const res = await t.api().get('/v1/auth/oauth/google/callback?code=x&state=forged-state-value-1234567890');
    expect(res.status).toBe(400);
    expect(res.body.error.code).toBe('invalid_state');
  });

  test('provider errors come back on the redirect, not as JSON', async () => {
    const agent = request.agent(t.app);
    const start = await agent.get(`/v1/auth/oauth/google/start?redirect_uri=${encodeURIComponent(REDIRECT)}`);
    const state = new URL(start.headers.location).searchParams.get('state');
    const res = await agent.get(`/v1/auth/oauth/google/callback?state=${state}`); // no code
    expect(res.status).toBe(302);
    expect(parseFragment(res.headers.location).get('error')).toBe('provider_denied');
  });
});
