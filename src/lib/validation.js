import { z } from 'zod';
import { badRequest } from './errors.js';
import { PASSWORD_MAX_LENGTH, PASSWORD_MIN_LENGTH } from './passwords.js';

export const emailSchema = z
  .string()
  .trim()
  .toLowerCase()
  .max(320)
  .pipe(z.email({ message: 'Must be a valid email address' }));

export const passwordSchema = z
  .string()
  .min(PASSWORD_MIN_LENGTH, `Must be at least ${PASSWORD_MIN_LENGTH} characters`)
  .max(PASSWORD_MAX_LENGTH, `Must be at most ${PASSWORD_MAX_LENGTH} characters`);

// For login, accept any non-empty string up to the max: the policy may have changed
// since the password was set, and the error must not hint at what the password is.
export const loginPasswordSchema = z.string().min(1).max(PASSWORD_MAX_LENGTH);

export const nameSchema = z.string().trim().max(100).optional();

export const tokenSchema = z.string().min(20).max(200);

// Parses input with a zod schema, or throws a 400 that lists every problem.
export function parse(schema, input) {
  const result = schema.safeParse(input ?? {});
  if (result.success) return result.data;
  throw badRequest(
    'invalid_request',
    'The request is not valid',
    result.error.issues.map((issue) => ({ field: issue.path.join('.') || null, message: issue.message })),
  );
}
