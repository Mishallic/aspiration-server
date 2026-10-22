import jwt from 'jsonwebtoken';
import config from '../src/config';
import {
  comparePassword,
  hashPassword,
  isEmail,
  publicUser,
  signToken,
  uniqueId,
  verifyToken,
} from '../src/helpers';

describe('passwords', () => {
  test('hashes with bcrypt and verifies', async () => {
    const hash = await hashPassword('correct horse');
    expect(hash).toMatch(/^\$2[aby]\$/);
    expect(hash).not.toContain('correct horse');
    await expect(comparePassword('correct horse', hash)).resolves.toBe(true);
    await expect(comparePassword('wrong horse', hash)).resolves.toBe(false);
  });

  test('salts each hash', async () => {
    const [a, b] = await Promise.all([hashPassword('same'), hashPassword('same')]);
    expect(a).not.toEqual(b);
  });
});

describe('tokens', () => {
  test('signToken round-trips through verifyToken', () => {
    const token = signToken({ id: 7, email: 'a@b.co' });
    expect(verifyToken(token).user).toEqual({ userId: 7, email: 'a@b.co' });
  });

  test('tokens expire', () => {
    const decoded = jwt.decode(signToken({ id: 1, email: 'a@b.co' }));
    expect(decoded.exp).toBeGreaterThan(decoded.iat);
  });

  test('a token signed with another secret is rejected', () => {
    const forged = jwt.sign({ user: { userId: 1, email: 'a@b.co' } }, `${config.jwtSecret}-other`);
    expect(() => verifyToken(forged)).toThrow();
  });
});

describe('validation and utilities', () => {
  test.each([
    ['user@example.com', true],
    ['  user@example.com  ', true],
    ['user@example', false],
    ['not an email', false],
    ['', false],
    [undefined, false],
    [42, false],
  ])('isEmail(%p) is %p', (value, expected) => {
    expect(isEmail(value)).toBe(expected);
  });

  test('publicUser strips secrets from plain objects and models', () => {
    const plain = { id: 1, email: 'a@b.co', password: 'x', verifyToken: 'y' };
    expect(publicUser(plain)).toEqual({ id: 1, email: 'a@b.co' });
    const model = { get: () => ({ ...plain }) };
    expect(publicUser(model)).toEqual({ id: 1, email: 'a@b.co' });
  });

  test('uniqueId returns the requested length from the expected alphabet', () => {
    const id = uniqueId(32);
    expect(id).toHaveLength(32);
    expect(id).toMatch(/^[A-Za-z0-9]+$/);
    expect(uniqueId()).toHaveLength(13);
    expect(uniqueId(32)).not.toEqual(id);
  });
});
