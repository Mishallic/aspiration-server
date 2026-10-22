// Browser- and Node-friendly client for aspiration-server. No dependencies.
//
//   import { createAuthClient } from 'aspiration-server/sdk';
//   const auth = createAuthClient({ baseUrl: 'https://auth.example.com' });
//   await auth.signUp({ email, password });
//   const res = await auth.fetchWithAuth('https://api.example.com/things');
//
// Tokens are kept in `storage` (localStorage in the browser, memory in Node). The
// access token is refreshed automatically when it is about to expire and once more
// if a fetchWithAuth call comes back 401.

const STORAGE_KEY = 'aspiration.session';
const EXPIRY_SKEW_MS = 30_000;

export class AuthError extends Error {
  constructor(status, code, message, details) {
    super(message || code || 'Request failed');
    this.name = 'AuthError';
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

function memoryStorage() {
  let value = null;
  return { getItem: () => value, setItem: (_, v) => { value = v; }, removeItem: () => { value = null; } };
}

function defaultStorage() {
  try {
    if (typeof localStorage !== 'undefined') {
      localStorage.getItem(STORAGE_KEY);
      return localStorage;
    }
  } catch {
    // localStorage can throw (private mode, blocked cookies); fall back to memory.
  }
  return memoryStorage();
}

function decodeExpiry(accessToken) {
  try {
    const [, payload] = accessToken.split('.');
    const json = JSON.parse(atob(payload.replace(/-/g, '+').replace(/_/g, '/')));
    return typeof json.exp === 'number' ? json.exp * 1000 : 0;
  } catch {
    return 0;
  }
}

export function createAuthClient({ baseUrl, storage, fetch: fetchImpl } = {}) {
  if (!baseUrl) throw new Error('createAuthClient requires a baseUrl');
  const root = baseUrl.replace(/\/$/, '');
  const store = storage ?? defaultStorage();
  const doFetch = fetchImpl ?? globalThis.fetch;
  const listeners = new Set();
  let refreshing = null;

  const readSession = () => {
    try {
      const raw = store.getItem(STORAGE_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  };

  let session = readSession();

  function setSession(next) {
    session = next;
    try {
      if (next) store.setItem(STORAGE_KEY, JSON.stringify(next));
      else store.removeItem(STORAGE_KEY);
    } catch {
      // Storage is best-effort; the in-memory copy still works for this page load.
    }
    for (const cb of listeners) cb(next?.user ?? null);
  }

  // Keeps user + tokens from an auth response, ignoring the no-token
  // "verification required" case.
  function saveAuthResult(body) {
    if (body?.accessToken && body?.refreshToken) {
      setSession({
        user: body.user,
        accessToken: body.accessToken,
        refreshToken: body.refreshToken,
        accessTokenExpiresAt: decodeExpiry(body.accessToken),
      });
    } else if (body?.user && session) {
      setSession({ ...session, user: body.user });
    }
    return body;
  }

  async function request(path, { method = 'GET', body, token, headers } = {}) {
    const res = await doFetch(`${root}${path}`, {
      method,
      headers: {
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...headers,
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    if (res.status === 204) return null;
    const data = await res.json().catch(() => null);
    if (!res.ok) {
      const err = data?.error ?? {};
      throw new AuthError(res.status, err.code, err.message, err.details);
    }
    return data;
  }

  // One refresh at a time: concurrent callers share the same in-flight promise.
  function refresh() {
    if (!session?.refreshToken) return Promise.reject(new AuthError(401, 'no_session', 'Not signed in'));
    refreshing ??= request('/v1/auth/refresh', { method: 'POST', body: { refreshToken: session.refreshToken } })
      .then(saveAuthResult)
      .catch((err) => {
        if (err.status === 401) setSession(null);
        throw err;
      })
      .finally(() => {
        refreshing = null;
      });
    return refreshing;
  }

  async function getAccessToken() {
    if (!session) return null;
    if (session.accessTokenExpiresAt && session.accessTokenExpiresAt - Date.now() > EXPIRY_SKEW_MS) {
      return session.accessToken;
    }
    await refresh();
    return session?.accessToken ?? null;
  }

  return {
    // --- state ---
    getUser: () => session?.user ?? null,
    getSession: () => session,
    isAuthenticated: () => Boolean(session?.refreshToken),
    onAuthChange(cb) {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },

    // --- sign-in / sign-out ---
    signUp: (input) => request('/v1/auth/signup', { method: 'POST', body: input }).then(saveAuthResult),
    signIn: ({ email, password }) =>
      request('/v1/auth/login', { method: 'POST', body: { email, password } }).then(saveAuthResult),
    signInWithIdToken: ({ provider, idToken }) =>
      request(`/v1/auth/oauth/${provider}/native`, { method: 'POST', body: { idToken } }).then(saveAuthResult),
    exchangeCode: (code) =>
      request('/v1/auth/oauth/exchange', { method: 'POST', body: { code } }).then(saveAuthResult),
    listProviders: () => request('/v1/auth/oauth/providers'),
    startWebSignIn: (provider, redirectUri) =>
      `${root}/v1/auth/oauth/${provider}/start?redirect_uri=${encodeURIComponent(redirectUri)}`,

    async signOut() {
      const token = session?.refreshToken;
      setSession(null);
      if (token) await request('/v1/auth/logout', { method: 'POST', body: { refreshToken: token } }).catch(() => {});
    },

    getAccessToken,
    refresh,

    // --- email flows ---
    requestPasswordReset: (email) => request('/v1/auth/password/forgot', { method: 'POST', body: { email } }),
    resetPassword: ({ token, newPassword }) =>
      request('/v1/auth/password/reset', { method: 'POST', body: { token, newPassword } }),
    verifyEmail: (token) => request('/v1/auth/verify-email', { method: 'POST', body: { token } }).then(saveAuthResult),
    resendVerification: (email) => request('/v1/auth/verify-email/resend', { method: 'POST', body: { email } }),

    // --- account (require a valid access token) ---
    async getProfile() {
      return request('/v1/me', { token: await getAccessToken() }).then(saveAuthResult);
    },
    async updateProfile(changes) {
      return request('/v1/me', { method: 'PATCH', body: changes, token: await getAccessToken() }).then(saveAuthResult);
    },
    async changePassword(input) {
      return request('/v1/me/change-password', { method: 'POST', body: input, token: await getAccessToken() }).then(
        saveAuthResult,
      );
    },
    async listSessions() {
      return request('/v1/me/sessions', { token: await getAccessToken() });
    },
    async logoutEverywhere() {
      await request('/v1/me/logout-all', { method: 'POST', token: await getAccessToken() });
      setSession(null);
    },
    async deleteAccount() {
      await request('/v1/me', { method: 'DELETE', token: await getAccessToken() });
      setSession(null);
    },

    // --- calling your own API ---
    // Adds the bearer token, and on a 401 refreshes once and retries.
    async fetchWithAuth(input, init = {}) {
      const withToken = async () => {
        const token = await getAccessToken();
        return doFetch(input, {
          ...init,
          headers: { ...(init.headers || {}), ...(token ? { authorization: `Bearer ${token}` } : {}) },
        });
      };
      let res = await withToken();
      if (res.status === 401 && session?.refreshToken) {
        try {
          await refresh();
          res = await withToken();
        } catch {
          // keep the original 401
        }
      }
      return res;
    },
  };
}

export default createAuthClient;
