import { createLocalJWKSet, decodeJwt, jwtVerify } from 'jose';
import { badRequest, serviceUnavailable } from '../lib/errors.js';

const JWKS_TTL_MS = 60 * 60 * 1000;

const GOOGLE = {
  authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
  tokenUrl: 'https://oauth2.googleapis.com/token',
  jwksUrl: 'https://www.googleapis.com/oauth2/v3/certs',
  issuers: ['https://accounts.google.com', 'accounts.google.com'],
  scope: 'openid email profile',
};
const APPLE = {
  jwksUrl: 'https://appleid.apple.com/auth/keys',
  issuer: 'https://appleid.apple.com',
};
const GITHUB = {
  authorizeUrl: 'https://github.com/login/oauth/authorize',
  tokenUrl: 'https://github.com/login/oauth/access_token',
  userUrl: 'https://api.github.com/user',
  emailsUrl: 'https://api.github.com/user/emails',
  scope: 'read:user user:email',
};

const asBool = (value) => value === true || value === 'true';

export function createOAuthProviders({ config, fetchImpl }) {
  const jwksCache = new Map();

  async function keySet(url) {
    const cached = jwksCache.get(url);
    if (cached && Date.now() - cached.at < JWKS_TTL_MS) return cached.set;
    const res = await fetchImpl(url, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) throw serviceUnavailable('provider_unavailable', 'Could not fetch provider signing keys');
    const set = createLocalJWKSet(await res.json());
    jwksCache.set(url, { set, at: Date.now() });
    return set;
  }

  async function verifyProviderJwt(idToken, { jwksUrl, issuer, issuers, audiences }) {
    if (!audiences.length) throw badRequest('provider_not_configured', 'This provider is not configured');
    try {
      const { payload } = await jwtVerify(idToken, await keySet(jwksUrl), {
        issuer: issuer ?? issuers,
        audience: audiences,
      });
      return payload;
    } catch (err) {
      if (err.status === 503) throw err;
      throw badRequest('invalid_provider_token', 'The provider identity token is invalid');
    }
  }

  const google = {
    hasWeb: () => Boolean(config.oauth.google),
    hasNative: () => config.oauth.googleNativeClientIds.length > 0,

    async verifyNativeToken(idToken) {
      const p = await verifyProviderJwt(idToken, {
        jwksUrl: GOOGLE.jwksUrl,
        issuers: GOOGLE.issuers,
        audiences: config.oauth.googleNativeClientIds,
      });
      return profileFromGoogle(p);
    },

    authorizeUrl({ state, redirectUri }) {
      const url = new URL(GOOGLE.authorizeUrl);
      url.search = new URLSearchParams({
        client_id: config.oauth.google.clientId,
        redirect_uri: redirectUri,
        response_type: 'code',
        scope: GOOGLE.scope,
        state,
        prompt: 'select_account',
      }).toString();
      return url.toString();
    },

    async handleCallback({ code, redirectUri }) {
      const res = await fetchImpl(GOOGLE.tokenUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: new URLSearchParams({
          code,
          client_id: config.oauth.google.clientId,
          client_secret: config.oauth.google.clientSecret,
          redirect_uri: redirectUri,
          grant_type: 'authorization_code',
        }),
        signal: AbortSignal.timeout(5000),
      });
      if (!res.ok) throw badRequest('provider_exchange_failed', 'Google rejected the authorization code');
      const { id_token: idToken } = await res.json();
      if (!idToken) throw badRequest('provider_exchange_failed', 'Google returned no identity token');
      const p = await verifyProviderJwt(idToken, {
        jwksUrl: GOOGLE.jwksUrl,
        issuers: GOOGLE.issuers,
        audiences: [config.oauth.google.clientId],
      });
      return profileFromGoogle(p);
    },
  };

  const apple = {
    hasWeb: () => false,
    hasNative: () => config.oauth.appleClientIds.length > 0,
    async verifyNativeToken(idToken) {
      const p = await verifyProviderJwt(idToken, {
        jwksUrl: APPLE.jwksUrl,
        issuer: APPLE.issuer,
        audiences: config.oauth.appleClientIds,
      });
      return {
        provider: 'apple',
        providerUserId: p.sub,
        email: p.email ?? null,
        emailVerified: asBool(p.email_verified),
        firstName: null,
        lastName: null,
        avatarUrl: null,
      };
    },
  };

  const github = {
    hasWeb: () => Boolean(config.oauth.github),
    hasNative: () => false,

    authorizeUrl({ state, redirectUri }) {
      const url = new URL(GITHUB.authorizeUrl);
      url.search = new URLSearchParams({
        client_id: config.oauth.github.clientId,
        redirect_uri: redirectUri,
        scope: GITHUB.scope,
        state,
        allow_signup: 'true',
      }).toString();
      return url.toString();
    },

    async handleCallback({ code, redirectUri }) {
      const tokenRes = await fetchImpl(GITHUB.tokenUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json' },
        body: new URLSearchParams({
          code,
          client_id: config.oauth.github.clientId,
          client_secret: config.oauth.github.clientSecret,
          redirect_uri: redirectUri,
        }),
        signal: AbortSignal.timeout(5000),
      });
      if (!tokenRes.ok) throw badRequest('provider_exchange_failed', 'GitHub rejected the authorization code');
      const { access_token: accessToken } = await tokenRes.json();
      if (!accessToken) throw badRequest('provider_exchange_failed', 'GitHub returned no access token');

      const headers = {
        authorization: `Bearer ${accessToken}`,
        accept: 'application/vnd.github+json',
        'user-agent': 'aspiration-server',
      };
      const [userRes, emailsRes] = await Promise.all([
        fetchImpl(GITHUB.userUrl, { headers, signal: AbortSignal.timeout(5000) }),
        fetchImpl(GITHUB.emailsUrl, { headers, signal: AbortSignal.timeout(5000) }),
      ]);
      if (!userRes.ok) throw badRequest('provider_exchange_failed', 'Could not read the GitHub profile');
      const profile = await userRes.json();
      const emails = emailsRes.ok ? await emailsRes.json() : [];
      const primary = Array.isArray(emails)
        ? emails.find((e) => e.primary && e.verified) ?? emails.find((e) => e.verified)
        : null;

      return {
        provider: 'github',
        providerUserId: String(profile.id),
        email: primary?.email ?? null,
        emailVerified: Boolean(primary),
        firstName: profile.name ? profile.name.split(' ')[0] : null,
        lastName: profile.name ? profile.name.split(' ').slice(1).join(' ') || null : null,
        avatarUrl: profile.avatar_url ?? null,
      };
    },
  };

  const providers = { google, apple, github };

  return {
    get(provider) {
      const impl = providers[provider];
      if (!impl) throw badRequest('unknown_provider', `Unknown provider: ${provider}`);
      return impl;
    },
    enabled() {
      return Object.entries(providers)
        .filter(([, impl]) => impl.hasWeb() || impl.hasNative())
        .map(([name]) => name);
    },
  };
}

function profileFromGoogle(payload) {
  return {
    provider: 'google',
    providerUserId: payload.sub,
    email: payload.email ?? null,
    emailVerified: asBool(payload.email_verified),
    firstName: payload.given_name ?? null,
    lastName: payload.family_name ?? null,
    avatarUrl: payload.picture ?? null,
  };
}

export { decodeJwt };
