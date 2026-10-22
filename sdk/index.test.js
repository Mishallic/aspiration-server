import { afterAll, beforeAll, describe, expect, test } from 'vitest';
import { createTestApp } from '../tests/helpers.js';
import { AuthError, createAuthClient } from './index.js';

// Boots a real server on an ephemeral port and drives it through the SDK over HTTP.
describe('JavaScript SDK', () => {
  let t;
  let server;
  let baseUrl;

  beforeAll(async () => {
    t = await createTestApp();
    await new Promise((resolve) => {
      server = t.app.listen(0, resolve);
    });
    baseUrl = `http://127.0.0.1:${server.address().port}`;
  });

  afterAll(async () => {
    await new Promise((resolve) => server.close(resolve));
    await t.close();
  });

  const newClient = () => createAuthClient({ baseUrl });

  test('signUp stores a session and exposes the user', async () => {
    const auth = newClient();
    expect(auth.isAuthenticated()).toBe(false);
    const result = await auth.signUp({ email: 'sdk@example.com', password: 'a good password' });
    expect(result.user.email).toBe('sdk@example.com');
    expect(auth.isAuthenticated()).toBe(true);
    expect(auth.getUser().email).toBe('sdk@example.com');
    expect(await auth.getAccessToken()).toEqual(expect.any(String));
  });

  test('signIn on a fresh client works and notifies listeners', async () => {
    const auth = newClient();
    const seen = [];
    auth.onAuthChange((user) => seen.push(user?.email ?? null));
    await auth.signIn({ email: 'sdk@example.com', password: 'a good password' });
    expect(auth.getUser().email).toBe('sdk@example.com');
    expect(seen).toContain('sdk@example.com');
  });

  test('a failed signIn throws a typed AuthError', async () => {
    const auth = newClient();
    await expect(auth.signIn({ email: 'sdk@example.com', password: 'wrong' })).rejects.toBeInstanceOf(AuthError);
    await expect(auth.signIn({ email: 'sdk@example.com', password: 'wrong' })).rejects.toMatchObject({
      status: 401,
      code: 'invalid_credentials',
    });
  });

  test('getAccessToken refreshes when the token is near expiry', async () => {
    const auth = newClient();
    await auth.signUp({ email: 'refresh-sdk@example.com', password: 'a good password' });
    const original = auth.getSession().accessToken;
    const originalRefresh = auth.getSession().refreshToken;

    // Pretend the access token has expired.
    auth.getSession().accessTokenExpiresAt = Date.now() - 1000;
    const token = await auth.getAccessToken();
    expect(token).not.toBe(original);
    // The refresh token rotated too.
    expect(auth.getSession().refreshToken).not.toBe(originalRefresh);
  });

  test('concurrent getAccessToken calls trigger only one refresh', async () => {
    const auth = newClient();
    await auth.signUp({ email: 'concurrent-sdk@example.com', password: 'a good password' });
    auth.getSession().accessTokenExpiresAt = Date.now() - 1000;
    const [a, b, c] = await Promise.all([auth.getAccessToken(), auth.getAccessToken(), auth.getAccessToken()]);
    expect(a).toBe(b);
    expect(b).toBe(c);
  });

  test('fetchWithAuth attaches the bearer token', async () => {
    const auth = newClient();
    await auth.signUp({ email: 'fetch-sdk@example.com', password: 'a good password' });
    const res = await auth.fetchWithAuth(`${baseUrl}/v1/me`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.user.email).toBe('fetch-sdk@example.com');
  });

  test('fetchWithAuth refreshes once and retries after a 401', async () => {
    const auth = newClient();
    await auth.signUp({ email: 'retry-sdk@example.com', password: 'a good password' });
    // Put a syntactically valid but unsigned token in place so the first call 401s;
    // getAccessToken thinks it is still fresh, so the retry path must do the refresh.
    const s = auth.getSession();
    s.accessToken = 'eyJhbGciOiJub25lIn0.eyJzdWIiOiJ4In0.';
    s.accessTokenExpiresAt = Date.now() + 10 * 60_000;
    const res = await auth.fetchWithAuth(`${baseUrl}/v1/me`);
    expect(res.status).toBe(200);
  });

  test('profile update and password change flow through the SDK', async () => {
    const auth = newClient();
    await auth.signUp({ email: 'profile-sdk@example.com', password: 'a good password' });
    const updated = await auth.updateProfile({ firstName: 'Ada' });
    expect(updated.user.firstName).toBe('Ada');

    await auth.changePassword({ currentPassword: 'a good password', newPassword: 'an even better password' });
    expect(auth.isAuthenticated()).toBe(true);

    const fresh = newClient();
    expect((await fresh.signIn({ email: 'profile-sdk@example.com', password: 'an even better password' })).user.email).toBe(
      'profile-sdk@example.com',
    );
  });

  test('signOut clears the session and revokes the refresh token', async () => {
    const auth = newClient();
    const { refreshToken } = await auth.signUp({ email: 'out-sdk@example.com', password: 'a good password' });
    await auth.signOut();
    expect(auth.isAuthenticated()).toBe(false);
    expect(auth.getUser()).toBeNull();

    const other = newClient();
    await expect(other.refresh.call(auth)).rejects.toBeDefined();
    // The server-side token is gone.
    const replay = await fetch(`${baseUrl}/v1/auth/refresh`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ refreshToken }),
    });
    expect(replay.status).toBe(401);
  });

  test('deleteAccount removes the user and clears the session', async () => {
    const auth = newClient();
    await auth.signUp({ email: 'delete-sdk@example.com', password: 'a good password' });
    await auth.deleteAccount();
    expect(auth.isAuthenticated()).toBe(false);
    const fresh = newClient();
    await expect(fresh.signIn({ email: 'delete-sdk@example.com', password: 'a good password' })).rejects.toMatchObject({
      status: 401,
    });
  });

  test('a custom storage object is used for persistence', async () => {
    const bag = new Map();
    const storage = {
      getItem: (k) => bag.get(k) ?? null,
      setItem: (k, v) => bag.set(k, v),
      removeItem: (k) => bag.delete(k),
    };
    const auth = createAuthClient({ baseUrl, storage });
    await auth.signUp({ email: 'storage-sdk@example.com', password: 'a good password' });
    expect([...bag.keys()]).toContain('aspiration.session');

    // A new client on the same storage restores the session.
    const restored = createAuthClient({ baseUrl, storage });
    expect(restored.getUser().email).toBe('storage-sdk@example.com');
  });
});
