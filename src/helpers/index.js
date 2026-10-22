import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import config from '../config';

export const successResponse = (req, res, data, code = 200) =>
  res.status(code).json({ code, data, success: true });

export const errorResponse = (req, res, errorMessage = 'Something went wrong', code = 500) =>
  res.status(code).json({ code, errorMessage, data: null, success: false });

export const hashPassword = (plain) => bcrypt.hash(plain, config.bcryptRounds);

export const comparePassword = (plain, hash) => bcrypt.compare(plain, hash);

export const signToken = (user) =>
  jwt.sign({ user: { userId: user.id, email: user.email } }, config.jwtSecret, {
    expiresIn: config.jwtExpiresIn,
  });

export const verifyToken = (token) => jwt.verify(token, config.jwtSecret);

export const isNonEmptyString = (value) => typeof value === 'string' && value.trim().length > 0;

export const isEmail = (value) =>
  isNonEmptyString(value) && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value.trim());

export const MIN_PASSWORD_LENGTH = 8;

const SECRET_FIELDS = ['password', 'verifyToken'];

export const publicUser = (user) => {
  const data = typeof user.get === 'function' ? user.get({ plain: true }) : { ...user };
  SECRET_FIELDS.forEach((field) => delete data[field]);
  return data;
};

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

// Cryptographically random, unlike the original Math.random() version.
export const uniqueId = (length = 13) => {
  const bytes = crypto.randomBytes(length);
  let result = '';
  for (let i = 0; i < length; i += 1) result += ALPHABET[bytes[i] % ALPHABET.length];
  return result;
};
