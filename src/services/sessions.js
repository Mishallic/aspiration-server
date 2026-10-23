import crypto from 'node:crypto';
import { Op } from 'sequelize';
import { SignJWT, jwtVerify, errors as joseErrors } from 'jose';
import { randomToken, sha256 } from '../lib/crypto.js';
import { unauthorized } from '../lib/errors.js';
import { SIGNING_ALG } from './keys.js';

const REFRESH_PREFIX = 'rt_';

// Access tokens: short-lived RS256 JWTs that any backend can verify with the JWKS.
// Refresh tokens: opaque random strings stored as SHA-256 hashes, rotated on every use.
// Presenting an already-rotated refresh token revokes its whole chain (its "family"),
// which cuts off whoever stole it as well as the legitimate holder.
export function createSessionService({ config, models, keys }) {
  const { User, RefreshToken } = models;
  const { issuer, audience, accessTokenTtlSeconds, refreshTokenTtlDays } = config.jwt;

  function issueAccessToken(user) {
    return new SignJWT({
      email: user.email,
      email_verified: Boolean(user.emailVerifiedAt),
      role: user.role,
    })
      .setProtectedHeader({ alg: SIGNING_ALG, kid: keys.signingKid(), typ: 'JWT' })
      .setIssuer(issuer)
      .setAudience(audience)
      .setSubject(user.id)
      .setIssuedAt()
      .setExpirationTime(`${accessTokenTtlSeconds}s`)
      .setJti(crypto.randomUUID())
      .sign(keys.signingKey());
  }

  async function verifyAccessToken(token) {
    const options = { issuer, audience, algorithms: [SIGNING_ALG] };
    try {
      const { payload } = await jwtVerify(token, keys.keySet, options);
      return payload;
    } catch (err) {
      if (err instanceof joseErrors.JWKSNoMatchingKey && (await keys.reloadIfStale())) {
        try {
          return (await jwtVerify(token, keys.keySet, options)).payload;
        } catch {
          // fall through to the generic error
        }
      }
      if (err instanceof joseErrors.JWTExpired) throw unauthorized('token_expired', 'Access token has expired');
      throw unauthorized('invalid_token', 'Access token is invalid');
    }
  }

  async function createSession(user, meta = {}, { familyId = crypto.randomUUID(), transaction } = {}) {
    const refreshToken = REFRESH_PREFIX + randomToken();
    await RefreshToken.create(
      {
        userId: user.id,
        familyId,
        tokenHash: sha256(refreshToken),
        expiresAt: new Date(Date.now() + refreshTokenTtlDays * 86_400_000),
        userAgent: meta.userAgent ? String(meta.userAgent).slice(0, 255) : null,
        ip: meta.ip ? String(meta.ip).slice(0, 64) : null,
      },
      { transaction },
    );
    return {
      accessToken: await issueAccessToken(user),
      refreshToken,
      tokenType: 'Bearer',
      expiresIn: accessTokenTtlSeconds,
    };
  }

  async function revokeFamily(familyId) {
    await RefreshToken.update({ revokedAt: new Date() }, { where: { familyId, revokedAt: null } });
  }

  const invalidRefresh = () => unauthorized('invalid_refresh_token', 'Refresh token is invalid or expired');

  async function refreshSession(rawToken, meta = {}) {
    if (typeof rawToken !== 'string' || !rawToken.startsWith(REFRESH_PREFIX)) throw invalidRefresh();
    const record = await RefreshToken.findOne({ where: { tokenHash: sha256(rawToken) } });
    if (!record) throw invalidRefresh();

    // A revoked token being presented again means the chain was rotated and this copy
    // was replayed (a likely theft). Sign the user out everywhere, which also bumps
    // tokensValidAfter so any access token the thief already holds stops working here.
    if (record.revokedAt) {
      await revokeAllSessions(record.userId);
      throw invalidRefresh();
    }
    if (record.expiresAt <= new Date()) throw invalidRefresh();

    // Conditional update, so two concurrent refreshes with the same token cannot both win.
    const [claimed] = await RefreshToken.update(
      { revokedAt: new Date() },
      { where: { id: record.id, revokedAt: null } },
    );
    if (claimed !== 1) {
      await revokeAllSessions(record.userId);
      throw invalidRefresh();
    }

    const user = await User.findByPk(record.userId);
    if (!user) throw invalidRefresh();
    return { session: await createSession(user, meta, { familyId: record.familyId }), user };
  }

  // Logout ends one session: the presented token and its whole rotation chain.
  async function revokeSession(rawToken) {
    if (typeof rawToken !== 'string') return;
    const record = await RefreshToken.findOne({ where: { tokenHash: sha256(rawToken) } });
    if (record) await revokeFamily(record.familyId);
  }

  // Signs the user out everywhere. Access tokens issued before now stop working on this
  // server at once; other backends that only check the JWT accept them until they expire.
  // Stored at full precision so the middleware can reject tokens issued in the same
  // second as the revocation (see requireAuth).
  async function revokeAllSessions(userId, { transaction } = {}) {
    await RefreshToken.update(
      { revokedAt: new Date() },
      { where: { userId, revokedAt: null }, transaction },
    );
    await User.update({ tokensValidAfter: new Date() }, { where: { id: userId }, transaction });
  }

  // Delete a refresh token only once it has expired, never merely because it was
  // revoked: a revoked row is the evidence that detects reuse of a stolen token, and
  // it must live for the family's full lifetime (up to REFRESH_TOKEN_TTL_DAYS).
  async function pruneExpired() {
    await RefreshToken.destroy({ where: { expiresAt: { [Op.lt]: new Date() } } });
  }

  return {
    issueAccessToken,
    verifyAccessToken,
    createSession,
    refreshSession,
    revokeSession,
    revokeAllSessions,
    pruneExpired,
  };
}
