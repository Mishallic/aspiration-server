import express from 'express';
import { z } from 'zod';
import { badRequest } from '../lib/errors.js';
import { hashPassword } from '../lib/passwords.js';
import { toPublicUser } from '../lib/users.js';
import { emailSchema, parse, passwordSchema, tokenSchema } from '../lib/validation.js';

const emailOnlySchema = z.object({ email: emailSchema });
const verifySchema = z.object({ token: tokenSchema });
const resetSchema = z.object({ token: tokenSchema, newPassword: passwordSchema });

export function emailRoutes(ctx) {
  const { models, services, rateLimits } = ctx;
  const { User } = models;
  const router = express.Router();
  const emailLimits = [rateLimits.emailPerIp, rateLimits.emailPerAddress];

  router.post('/verify-email', rateLimits.tokenUse, async (req, res) => {
    const { token } = parse(verifySchema, req.body);
    const user = await services.emailFlows.verifyEmail(token);
    if (!user) throw badRequest('invalid_token', 'The verification link is invalid or has expired');
    res.json({ user: toPublicUser(user) });
  });

  // Respond 204 first, then do the lookup and token work off the request path (via
  // ctx.background). The response time is therefore independent of whether the address
  // has an account, so it cannot be timed to tell registered addresses from unknown ones.

  // Resend. Always 204: it must not reveal whether the address has an account.
  router.post('/verify-email/resend', emailLimits, (req, res) => {
    const { email } = parse(emailOnlySchema, req.body);
    res.status(204).end();
    ctx.background.run(
      User.findOne({ where: { email } }).then((user) =>
        user && !user.emailVerifiedAt ? services.emailFlows.sendVerification(user) : null,
      ),
    );
  });

  // Request a reset. Always 204, for the same reason.
  router.post('/password/forgot', emailLimits, (req, res) => {
    const { email } = parse(emailOnlySchema, req.body);
    res.status(204).end();
    ctx.background.run(
      User.findOne({ where: { email } }).then((user) => (user ? services.emailFlows.sendPasswordReset(user) : null)),
    );
  });

  router.post('/password/reset', rateLimits.tokenUse, async (req, res) => {
    // Validate the new password BEFORE spending the single-use token, so a weak
    // password does not waste a valid reset link.
    const { token, newPassword } = parse(resetSchema, req.body);
    const user = await services.emailFlows.consumePasswordReset(token);
    if (!user) throw badRequest('invalid_token', 'The reset link is invalid or has expired');

    await user.update({
      passwordHash: await hashPassword(newPassword),
      emailVerifiedAt: user.emailVerifiedAt ?? new Date(),
    });
    // A reset ends every existing session, cutting off anyone who had access.
    await services.sessions.revokeAllSessions(user.id);
    res.status(204).end();
  });

  return router;
}
