import crypto from 'node:crypto';
import {
  calculateJwkThumbprint,
  createLocalJWKSet,
  exportJWK,
  generateKeyPair,
  importJWK,
  importPKCS8,
} from 'jose';

export const SIGNING_ALG = 'RS256';
const RELOAD_THROTTLE_MS = 30_000;

async function recordFromPem(pem) {
  const privateKey = await importPKCS8(pem, SIGNING_ALG);
  const publicJwk = crypto.createPublicKey(crypto.createPrivateKey(pem)).export({ format: 'jwk' });
  const kid = await calculateJwkThumbprint(publicJwk);
  return { kid, privateKey, publicJwk: { ...publicJwk, kid, alg: SIGNING_ALG, use: 'sig' } };
}

async function generateRecord() {
  const { publicKey, privateKey } = await generateKeyPair(SIGNING_ALG, { modulusLength: 2048, extractable: true });
  const publicJwk = await exportJWK(publicKey);
  const kid = await calculateJwkThumbprint(publicJwk);
  return {
    kid,
    alg: SIGNING_ALG,
    publicJwk: { ...publicJwk, kid, alg: SIGNING_ALG, use: 'sig' },
    privateJwk: await exportJWK(privateKey),
  };
}

// Holds the active signing key and the public key set published at /.well-known/jwks.json.
// Without SIGNING_KEY, a key pair is generated on first start and stored in the database.
export function createKeyStore({ config, sequelize, models }) {
  const { SigningKey } = models;
  let signing = null;
  let jwks = { keys: [] };
  let localSet = createLocalJWKSet(jwks);
  let lastLoad = 0;

  async function load() {
    const published = [];
    if (config.jwt.signingKeyPem) {
      const record = await recordFromPem(config.jwt.signingKeyPem);
      signing = { kid: record.kid, key: record.privateKey };
      published.push(record.publicJwk);
    } else {
      let active = await SigningKey.findOne({ where: { active: true }, order: [['createdAt', 'DESC']] });
      if (!active) active = await SigningKey.create({ ...(await generateRecord()), active: true });
      signing = { kid: active.kid, key: await importJWK(active.privateJwk, SIGNING_ALG) };
    }
    // Keys that are no longer active stay published until retired, so tokens they
    // signed keep verifying after a rotation.
    const stored = await SigningKey.findAll({ where: { retiredAt: null }, order: [['createdAt', 'DESC']] });
    for (const key of stored) {
      if (!published.some((jwk) => jwk.kid === key.kid)) published.push(key.publicJwk);
    }
    jwks = { keys: published };
    localSet = createLocalJWKSet(jwks);
    lastLoad = Date.now();
  }

  // The previous active key stays published; keys older than that are retired.
  async function rotate() {
    if (config.jwt.signingKeyPem) {
      throw new Error('SIGNING_KEY is set in the environment. Rotate the key there instead.');
    }
    const record = await generateRecord();
    await sequelize.transaction(async (transaction) => {
      await SigningKey.update(
        { retiredAt: new Date() },
        { where: { active: false, retiredAt: null }, transaction },
      );
      await SigningKey.update({ active: false }, { where: { active: true }, transaction });
      await SigningKey.create({ ...record, active: true }, { transaction });
    });
    await load();
    return record.kid;
  }

  // A key created by another process (a rotation, or another instance) is picked up
  // the first time a token signed with it arrives.
  async function reloadIfStale() {
    if (Date.now() - lastLoad < RELOAD_THROTTLE_MS) return false;
    await load();
    return true;
  }

  return {
    load,
    rotate,
    reloadIfStale,
    signingKey: () => signing.key,
    signingKid: () => signing.kid,
    jwks: () => jwks,
    keySet: (...args) => localSet(...args),
  };
}
