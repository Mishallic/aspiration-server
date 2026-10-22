import { Op } from 'sequelize';
import { randomToken, sha256 } from '../lib/crypto.js';

export const PURPOSES = Object.freeze({
  VERIFY_EMAIL: 'verify_email',
  RESET_PASSWORD: 'reset_password',
  OAUTH_STATE: 'oauth_state',
  OAUTH_CODE: 'oauth_code',
});

// Single-use, expiring tokens for email links and the OAuth handoff.
// Only the SHA-256 hash is stored; the raw value exists only in the link or redirect.
export function createOneTimeTokenService({ models }) {
  const { OneTimeToken } = models;

  async function issue({ purpose, userId = null, data = null, ttlSeconds, transaction }) {
    const raw = randomToken();
    await OneTimeToken.create(
      {
        purpose,
        userId,
        data,
        tokenHash: sha256(raw),
        expiresAt: new Date(Date.now() + ttlSeconds * 1000),
      },
      { transaction },
    );
    return raw;
  }

  // Returns the token record if it was valid, unused and unexpired, and marks it used.
  // The conditional update makes consumption atomic, so a token works exactly once.
  async function consume({ purpose, raw, transaction }) {
    if (typeof raw !== 'string' || raw.length < 20 || raw.length > 200) return null;
    const record = await OneTimeToken.findOne({ where: { tokenHash: sha256(raw), purpose }, transaction });
    if (!record || record.usedAt || record.expiresAt <= new Date()) return null;
    const [claimed] = await OneTimeToken.update(
      { usedAt: new Date() },
      { where: { id: record.id, usedAt: null }, transaction },
    );
    return claimed === 1 ? record : null;
  }

  // Invalidates outstanding tokens, for example older reset links once a new one is sent.
  async function revokeAll({ userId, purpose, transaction }) {
    await OneTimeToken.update(
      { usedAt: new Date() },
      { where: { userId, purpose, usedAt: null }, transaction },
    );
  }

  async function pruneExpired() {
    await OneTimeToken.destroy({ where: { expiresAt: { [Op.lt]: new Date(Date.now() - 86_400_000) } } });
  }

  return { issue, consume, revokeAll, pruneExpired };
}
