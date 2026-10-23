import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { bearer, createTestApp, signUp } from './helpers.js';

// Regression tests for findings from the adversarial security review.
describe('session revocation precision and reuse', () => {
  let t;
  beforeAll(async () => {
    t = await createTestApp();
  });
  afterAll(() => t.close());

  test('a token issued in the same second as revoke-all is rejected', async () => {
    const { user, accessToken } = await signUp(t.app, { email: 'sametick@example.com' });
    // Revoke in the same wall-clock second the token was issued; the millisecond
    // comparison must still reject it (no same-second bypass window).
    await t.ctx.services.sessions.revokeAllSessions(user.id);
    const res = await t.api().get('/v1/me').set(bearer(accessToken));
    expect(res.status).toBe(401);
    expect(res.body.error.code).toBe('token_revoked');
  });

  test('reusing a rotated refresh token also kills the thief\'s existing access token', async () => {
    const victim = await signUp(t.app, { email: 'thief@example.com' });

    // Attacker refreshes with the stolen token, getting a fresh access token.
    const stolen = await t.api().post('/v1/auth/refresh').send({ refreshToken: victim.refreshToken });
    expect(stolen.status).toBe(200);
    const attackerAccess = stolen.body.accessToken;
    expect((await t.api().get('/v1/me').set(bearer(attackerAccess))).status).toBe(200);

    // The victim's client still holds the original token and refreshes: reuse detected.
    const detect = await t.api().post('/v1/auth/refresh').send({ refreshToken: victim.refreshToken });
    expect(detect.status).toBe(401);

    // The attacker's already-issued access token must now be rejected too.
    const after = await t.api().get('/v1/me').set(bearer(attackerAccess));
    expect(after.status).toBe(401);
    expect(after.body.error.code).toBe('token_revoked');
  });

  test('revoked refresh-token rows are kept until expiry so reuse stays detectable', async () => {
    const { user, refreshToken } = await signUp(t.app, { email: 'prune@example.com' });
    await t.api().post('/v1/auth/refresh').send({ refreshToken }); // rotates -> old row revoked
    await t.ctx.services.sessions.pruneExpired();
    // The revoked row still exists (its expiresAt is far in the future).
    const revokedRows = await t.ctx.models.RefreshToken.count({
      where: { userId: user.id },
    });
    expect(revokedRows).toBeGreaterThanOrEqual(2);
  });
});

describe('reset-password page escaping', () => {
  let t;
  beforeAll(async () => {
    t = await createTestApp();
  });
  afterAll(() => t.close());

  test('a token that tries to close the <script> tag is neutralised', async () => {
    const malicious = '</script><img src=x onerror=alert(1)>';
    const res = await t.api().get(`/reset-password?token=${encodeURIComponent(malicious)}`);
    expect(res.status).toBe(200);
    // The raw closing tag must never appear literally in the HTML...
    expect(res.text).not.toContain('</script><img');
    // ...it is emitted as an escaped unicode sequence inside the script string instead.
    expect(res.text).toContain('\\u003c');
    // And the page keeps its nonce CSP, which blocks inline execution as defence in depth.
    expect(res.headers['content-security-policy']).toMatch(/script-src 'nonce-/);
  });
});
