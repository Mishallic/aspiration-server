import crypto from 'node:crypto';

// 32 random bytes, URL-safe. Used for refresh tokens, email links and OAuth codes.
export const randomToken = (bytes = 32) => crypto.randomBytes(bytes).toString('base64url');

// Tokens are stored only as SHA-256 hashes, so a database leak does not leak usable tokens.
// They carry 256 bits of entropy, so a fast hash is enough; no salt or KDF is needed.
export const sha256 = (value) => crypto.createHash('sha256').update(value).digest('hex');

export const sha256Base64Url = (value) => crypto.createHash('sha256').update(value).digest('base64url');

export function safeEqual(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

export const hmacSha256 = (secret, value) => crypto.createHmac('sha256', secret).update(value).digest('hex');
