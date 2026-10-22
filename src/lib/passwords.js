import argon2 from 'argon2';

// OWASP's recommended Argon2id settings: 19 MiB memory, 2 iterations, 1 lane.
const OPTIONS = { type: argon2.argon2id, memoryCost: 19456, timeCost: 2, parallelism: 1 };

export const PASSWORD_MIN_LENGTH = 8;
export const PASSWORD_MAX_LENGTH = 256;

export const hashPassword = (password) => argon2.hash(password, OPTIONS);

let dummyHash;

// Always does the same amount of work, so response time does not reveal
// whether an account exists or has a password.
export async function verifyPassword(hash, password) {
  if (!hash) {
    dummyHash ??= await argon2.hash('dummy-password-for-timing', OPTIONS);
    await argon2.verify(dummyHash, password);
    return false;
  }
  try {
    return await argon2.verify(hash, password);
  } catch {
    return false;
  }
}
