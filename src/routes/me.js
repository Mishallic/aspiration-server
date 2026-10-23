import express from 'express';
import { z } from 'zod';
import { requireAuth } from '../middleware/auth.js';
import { badRequest, unauthorized } from '../lib/errors.js';
import { hashPassword, verifyPassword } from '../lib/passwords.js';
import { toPublicUser } from '../lib/users.js';
import { nameSchema, parse, passwordSchema } from '../lib/validation.js';

const updateSchema = z
  .object({ firstName: nameSchema, lastName: nameSchema, avatarUrl: z.url().max(2048).nullish() })
  .refine((data) => Object.keys(data).length > 0, { message: 'No fields to update' });

// Changing a password needs the current one, unless the account has none yet
// (a social-only account setting its first password).
const changePasswordSchema = z.object({
  currentPassword: z.string().min(1).max(256).optional(),
  newPassword: passwordSchema,
});

export function meRoutes(ctx) {
  const { models, services } = ctx;
  const router = express.Router();
  router.use(requireAuth(ctx));

  router.get('/', (req, res) => res.json({ user: toPublicUser(req.user) }));

  router.patch('/', async (req, res) => {
    const input = parse(updateSchema, req.body);
    await req.user.update(input);
    res.json({ user: toPublicUser(req.user) });
  });

  router.post('/change-password', async (req, res) => {
    const { currentPassword, newPassword } = parse(changePasswordSchema, req.body);

    if (req.user.passwordHash) {
      if (!currentPassword) throw badRequest('current_password_required', 'The current password is required');
      if (!(await verifyPassword(req.user.passwordHash, currentPassword))) {
        throw unauthorized('invalid_credentials', 'The current password is incorrect');
      }
    }

    await req.user.update({ passwordHash: await hashPassword(newPassword) });
    // A password change signs out every other session; this one gets a fresh pair.
    await services.sessions.revokeAllSessions(req.user.id);
    const session = await services.sessions.createSession(req.user, { ip: req.ip, userAgent: req.get('user-agent') });
    res.json({ user: toPublicUser(req.user), ...session });
  });

  // Active sessions, so a user can see and end their logins on other devices.
  router.get('/sessions', async (req, res) => {
    const rows = await models.RefreshToken.findAll({
      where: { userId: req.user.id, revokedAt: null },
      order: [['createdAt', 'DESC']],
    });
    res.json({
      sessions: rows
        .filter((row) => row.expiresAt > new Date())
        .map((row) => ({
          id: row.id,
          createdAt: row.createdAt,
          lastSeenIp: row.ip,
          userAgent: row.userAgent,
          expiresAt: row.expiresAt,
        })),
      currentIssuedAt: new Date(req.tokenPayload.iat * 1000),
    });
  });

  router.post('/logout-all', async (req, res) => {
    await services.sessions.revokeAllSessions(req.user.id);
    res.status(204).end();
  });

  // Account deletion. Required by the App Store for any app with sign-up, and by GDPR.
  // Cascades to identities, refresh tokens and one-time tokens via foreign keys.
  router.delete('/', async (req, res) => {
    const { id, email } = req.user;
    await req.user.destroy();
    services.webhooks.emit('user.deleted', { user: { id, email } });
    res.status(204).end();
  });

  return router;
}
