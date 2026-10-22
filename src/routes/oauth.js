import express from 'express';
import { z } from 'zod';
import { badRequest, notFound } from '../lib/errors.js';
import { toPublicUser } from '../lib/users.js';
import { parse } from '../lib/validation.js';
import { PURPOSES } from '../services/oneTimeTokens.js';
import { requestMeta } from './auth.js';

const OAUTH_STATE_TTL = 600;
const OAUTH_CODE_TTL = 120;
const PROVIDERS = new Set(['google', 'github', 'apple']);

const nativeSchema = z.object({ idToken: z.string().min(10).max(8192) });
const exchangeSchema = z.object({ code: z.string().min(20).max(200) });

function assertProvider(name) {
  if (!PROVIDERS.has(name)) throw notFound('unknown_provider', `Unknown provider: ${name}`);
}

export function oauthRoutes(ctx) {
  const { config, services, rateLimits } = ctx;
  const router = express.Router();

  const callbackUrl = (provider) => `${config.publicUrl}/v1/auth/oauth/${provider}/callback`;

  // Exact match against the configured allowlist. Without it, the web flow is disabled,
  // because sending a code to an unvetted URL would hand an attacker the account.
  function assertAllowedRedirect(redirectUri) {
    if (typeof redirectUri !== 'string' || !config.allowedRedirectUrls.includes(redirectUri.replace(/\/$/, ''))) {
      throw badRequest('invalid_redirect_uri', 'redirect_uri is not in ALLOWED_REDIRECT_URLS');
    }
  }

  function appendFragment(base, params) {
    const url = new URL(base);
    url.hash = new URLSearchParams(params).toString();
    return url.toString();
  }

  router.get('/providers', (req, res) => {
    res.json({
      providers: services.oauthProviders.enabled().map((name) => {
        const impl = services.oauthProviders.get(name);
        return { provider: name, native: impl.hasNative(), web: impl.hasWeb() };
      }),
    });
  });

  // Native: a mobile app signs in with the provider SDK and posts the ID token here.
  router.post('/:provider/native', rateLimits.credentials, async (req, res) => {
    assertProvider(req.params.provider);
    const impl = services.oauthProviders.get(req.params.provider);
    if (!impl.hasNative()) throw badRequest('provider_not_configured', 'Native sign-in is not configured');

    const { idToken } = parse(nativeSchema, req.body);
    const profile = await impl.verifyNativeToken(idToken);
    const { user, session } = await services.accounts.signInWithProvider(profile, requestMeta(req));
    res.json({ user: toPublicUser(user), ...session });
  });

  // Web step 1: start the redirect. Stores the validated redirect target in a
  // single-use state token, so the callback trusts only what we issued.
  router.get('/:provider/start', async (req, res) => {
    assertProvider(req.params.provider);
    const impl = services.oauthProviders.get(req.params.provider);
    if (!impl.hasWeb()) throw badRequest('provider_not_configured', 'Web sign-in is not configured');

    assertAllowedRedirect(req.query.redirect_uri);
    const redirectUri = req.query.redirect_uri.replace(/\/$/, '');

    const state = await services.oneTimeTokens.issue({
      purpose: PURPOSES.OAUTH_STATE,
      data: { provider: req.params.provider, redirectUri },
      ttlSeconds: OAUTH_STATE_TTL,
    });
    res.redirect(impl.authorizeUrl({ state, redirectUri: callbackUrl(req.params.provider) }));
  });

  // Web step 2: the provider redirects back here. We exchange the code, sign the user
  // in, mint a short one-time app code, and hand it to the client in the URL fragment.
  router.get('/:provider/callback', async (req, res, next) => {
    assertProvider(req.params.provider);
    const stateRecord = await services.oneTimeTokens.consume({
      purpose: PURPOSES.OAUTH_STATE,
      raw: typeof req.query.state === 'string' ? req.query.state : '',
    });
    if (!stateRecord || stateRecord.data?.provider !== req.params.provider) {
      throw badRequest('invalid_state', 'The sign-in state is missing, expired or already used');
    }
    const { redirectUri } = stateRecord.data;

    try {
      if (typeof req.query.code !== 'string') throw badRequest('provider_denied', 'Sign-in was cancelled');
      const impl = services.oauthProviders.get(req.params.provider);
      const profile = await impl.handleCallback({ code: req.query.code, redirectUri: callbackUrl(req.params.provider) });
      const { user, created } = await services.accounts.findOrCreateFromProvider(profile);
      if (created) services.webhooks.emit('user.created', { user: toPublicUser(user), provider: profile.provider });

      const appCode = await services.oneTimeTokens.issue({
        purpose: PURPOSES.OAUTH_CODE,
        userId: user.id,
        ttlSeconds: OAUTH_CODE_TTL,
      });
      res.redirect(appendFragment(redirectUri, { code: appCode }));
    } catch (err) {
      // Deliver provider errors to the client via the (already validated) redirect,
      // so a user who denies consent lands back in the app instead of on a JSON page.
      if (err.status === 400) return res.redirect(appendFragment(redirectUri, { error: err.code }));
      return next(err);
    }
  });

  // Web step 3: the client trades the one-time code for real tokens.
  router.post('/exchange', rateLimits.credentials, async (req, res) => {
    const { code } = parse(exchangeSchema, req.body);
    const record = await services.oneTimeTokens.consume({ purpose: PURPOSES.OAUTH_CODE, raw: code });
    if (!record?.userId) throw badRequest('invalid_code', 'The sign-in code is invalid or expired');
    const user = await ctx.models.User.findByPk(record.userId);
    if (!user) throw badRequest('invalid_code', 'The sign-in code is invalid or expired');
    const session = await services.sessions.createSession(user, requestMeta(req));
    res.json({ user: toPublicUser(user), ...session });
  });

  return router;
}
