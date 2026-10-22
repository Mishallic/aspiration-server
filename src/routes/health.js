import express from 'express';

export function healthRoutes({ sequelize }) {
  const router = express.Router();
  router.get('/health', async (req, res) => {
    try {
      await sequelize.authenticate();
      res.set('Cache-Control', 'no-store').json({ status: 'ok' });
    } catch {
      res.status(503).set('Cache-Control', 'no-store').json({ status: 'unavailable' });
    }
  });
  return router;
}
