import express from 'express';
import { z } from 'zod';
import { conflict, forbidden, unauthorized } from '../lib/errors.js';
import { hashPassword, verifyPassword } from '../lib/passwords.js';
import { toPublicUser } from '../lib/users.js';
import { emailSchema, loginPasswordSchema, nameSchema, parse, passwordSchema } from '../lib/validation.js';

export const MAX_FAILED_LOGINS = 10;
export const LOCKOUT_MINUTES = 15;

const signupSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  firstName: nameSchema,
  lastName: nameSchema,
});
const loginSchema = z.object({ email: emailSchema, password: loginPasswordSchema });
const refreshSchema = z.object({ refreshToken: z.string().min(1).max(200) });

export const requestMeta = (req) => ({ ip: req.ip, userAgent: req.get('user-agent') });

export function authRoutes(ctx) {
  const { config, models, services, rateLimits } = ctx;
  const { User } = models;
  const router = express.Router();

  router.post('/signup', rateLimits.credentials, async (req, res) => {
    const input = parse(signupSchema, req.body);
    if (await User.findOne({ where: { email: input.email } })) {
      throw conflict('email_taken', 'An account with this email already exists');
    }
    let user;
    try {
      user = await User.create({
        email: input.email,
        passwordHash: await hashPassword(input.password),
        firstName: input.firstName || null,
        lastName: input.lastName || null,
      });
    } catch (err) {
      // Two sign-ups for the same email at the same moment: the unique index decides.
      if (err.name === 'SequelizeUniqueConstraintError') {
        throw conflict('email_taken', 'An account with this email already exists');
      }
      throw err;
    }

    await services.emailFlows.sendVerification(user);
    services.webhooks.emit('user.created', { user: toPublicUser(user) });

    if (config.email.requireVerification) {
      return res.status(201).json({ user: toPublicUser(user), verificationRequired: true });
    }
    const session = await services.sessions.createSession(user, requestMeta(req));
    return res.status(201).json({ user: toPublicUser(user), ...session });
  });

  router.post('/login', rateLimits.credentials, async (req, res) => {
    const input = parse(loginSchema, req.body);
    const user = await User.findOne({ where: { email: input.email } });
    const locked = Boolean(user?.lockedUntil && user.lockedUntil > new Date());

    // Always run a password verification (a dummy hash when the user or password is
    // absent), so response time does not reveal whether the account exists or is
    // locked. The lock state is never surfaced to an unauthenticated caller.
    const valid = await verifyPassword(user?.passwordHash, input.password);
    if (!valid) {
      // Count failures only while not already locked, so an attacker cannot keep
      // extending the lock. Same generic answer whether or not the account exists.
      if (user && !locked) await recordFailedLogin(user);
      throw unauthorized('invalid_credentials', 'Incorrect email or password');
    }

    // The correct password always signs in and clears any lock. Lockout throttles
    // wrong guesses; it must never lock out the real owner (a targeted-lockout DoS).
    if (user.failedLoginCount || user.lockedUntil) {
      await user.update({ failedLoginCount: 0, lockedUntil: null });
    }
    if (config.email.requireVerification && !user.emailVerifiedAt) {
      throw forbidden('email_not_verified', 'Confirm your email address before signing in');
    }

    const session = await services.sessions.createSession(user, requestMeta(req));
    return res.json({ user: toPublicUser(user), ...session });
  });

  // Records a failed attempt and locks the account once the threshold is reached.
  // The lock only suppresses further failure counting; a correct password still
  // signs in (see /login), so this cannot be used to lock a victim out.
  async function recordFailedLogin(user) {
    await user.increment('failedLoginCount');
    await user.reload();
    if (user.failedLoginCount >= MAX_FAILED_LOGINS) {
      await user.update({
        failedLoginCount: 0,
        lockedUntil: new Date(Date.now() + LOCKOUT_MINUTES * 60_000),
      });
    }
  }

  router.post('/refresh', rateLimits.refresh, async (req, res) => {
    const { refreshToken } = parse(refreshSchema, req.body);
    const { session, user } = await services.sessions.refreshSession(refreshToken, requestMeta(req));
    return res.json({ user: toPublicUser(user), ...session });
  });

  // Always 204, so logout never reveals whether a token existed.
  router.post('/logout', rateLimits.refresh, async (req, res) => {
    const { refreshToken } = parse(refreshSchema, req.body);
    await services.sessions.revokeSession(refreshToken);
    return res.status(204).end();
  });

  return router;
}
