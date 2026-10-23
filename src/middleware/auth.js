import { forbidden, unauthorized } from '../lib/errors.js';

const BEARER = /^Bearer\s+([A-Za-z0-9\-_.]+)$/i;

// Verifies the access token and loads the user. Unlike a third-party backend that only
// checks the JWT signature, this also rejects tokens for deleted users and tokens
// issued before the user signed out everywhere or changed their password.
export function requireAuth({ models, services }) {
  return async (req, res, next) => {
    const match = BEARER.exec(req.get('authorization') ?? '');
    if (!match) throw unauthorized('missing_token', 'Send the access token as "Authorization: Bearer <token>"');

    const payload = await services.sessions.verifyAccessToken(match[1]);
    const user = await models.User.findByPk(payload.sub);
    if (!user) throw unauthorized('invalid_token', 'Access token is invalid');
    // iat is floored to the second; compare in milliseconds and reject ties so a token
    // minted in the same second as a revocation does not slip through.
    if (user.tokensValidAfter && payload.iat * 1000 < user.tokensValidAfter.getTime()) {
      throw unauthorized('token_revoked', 'Access token has been revoked');
    }

    req.user = user;
    req.tokenPayload = payload;
    next();
  };
}

export function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') throw forbidden('admin_required', 'Admin access is required');
  next();
}
