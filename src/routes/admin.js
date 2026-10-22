import express from 'express';
import { z } from 'zod';
import { Op } from 'sequelize';
import { requireAdmin, requireAuth } from '../middleware/auth.js';
import { forbidden, notFound } from '../lib/errors.js';
import { toPublicUser } from '../lib/users.js';
import { parse } from '../lib/validation.js';

const listSchema = z.object({
  page: z.coerce.number().int().min(1).default(1),
  limit: z.coerce.number().int().min(1).max(100).default(20),
  search: z.string().trim().max(320).optional(),
});

const roleSchema = z.object({ role: z.enum(['user', 'admin']) });

export function adminRoutes(ctx) {
  const { models, services } = ctx;
  const { User } = models;
  const router = express.Router();
  router.use(requireAuth(ctx), requireAdmin);

  router.get('/users', async (req, res) => {
    const { page, limit, search } = parse(listSchema, req.query);
    const where = search ? { email: { [Op.like]: `%${search.toLowerCase()}%` } } : undefined;
    const { count, rows } = await User.findAndCountAll({
      where,
      order: [['createdAt', 'DESC']],
      offset: (page - 1) * limit,
      limit,
    });
    res.json({
      users: rows.map(toPublicUser),
      page,
      limit,
      total: count,
      totalPages: Math.ceil(count / limit),
    });
  });

  router.get('/users/:id', async (req, res) => {
    const user = await User.findByPk(req.params.id);
    if (!user) throw notFound('user_not_found', 'No user with that id');
    res.json({ user: toPublicUser(user) });
  });

  router.patch('/users/:id/role', async (req, res) => {
    const { role } = parse(roleSchema, req.body);
    const user = await User.findByPk(req.params.id);
    if (!user) throw notFound('user_not_found', 'No user with that id');
    await user.update({ role });
    // The new role takes effect in the next access token, so end current sessions.
    await services.sessions.revokeAllSessions(user.id);
    res.json({ user: toPublicUser(user) });
  });

  router.delete('/users/:id', async (req, res) => {
    if (req.params.id === req.user.id) {
      throw forbidden('cannot_delete_self', 'Delete your own account from the account endpoint, not here');
    }
    const user = await User.findByPk(req.params.id);
    if (!user) throw notFound('user_not_found', 'No user with that id');
    const { id, email } = user;
    await user.destroy();
    services.webhooks.emit('user.deleted', { user: { id, email } });
    res.status(204).end();
  });

  return router;
}
