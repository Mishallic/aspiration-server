import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { createRateLimits } from './middleware/rateLimits.js';
import { createErrorHandler, notFoundHandler } from './middleware/errors.js';
import { healthRoutes } from './routes/health.js';
import { wellKnownRoutes } from './routes/wellKnown.js';
import { authRoutes } from './routes/auth.js';
import { emailRoutes } from './routes/email.js';
import { oauthRoutes } from './routes/oauth.js';
import { meRoutes } from './routes/me.js';
import { adminRoutes } from './routes/admin.js';
import { pageRoutes } from './routes/pages.js';

function parseTrustProxy(value) {
  if (value === undefined) return undefined;
  if (value === 'true') return true;
  if (value === 'false') return false;
  if (/^\d+$/.test(value)) return Number(value);
  return value;
}

function corsOptions(config) {
  const origins = config.corsOrigins;
  if (origins.includes('*')) return { origin: '*' };
  if (origins.length) return { origin: origins };
  // No list configured: allow every origin while developing, none in production.
  return { origin: !config.isProduction };
}

export function createApp(ctx) {
  const { config } = ctx;
  const app = express();
  ctx.rateLimits ??= createRateLimits(config);

  app.disable('x-powered-by');
  const trustProxy = parseTrustProxy(config.trustProxy);
  if (trustProxy !== undefined) app.set('trust proxy', trustProxy);

  app.use(helmet());
  app.use(cors({ ...corsOptions(config), maxAge: 600 }));
  app.use(express.json({ limit: '20kb' }));
  app.use(cookieParser());

  app.use(healthRoutes(ctx));
  app.use(wellKnownRoutes(ctx));
  app.use(pageRoutes(ctx));

  const v1 = express.Router();
  v1.use(ctx.rateLimits.api);
  // Responses carry tokens and personal data: never cache them.
  v1.use((req, res, next) => {
    res.set('Cache-Control', 'no-store');
    next();
  });
  v1.use('/auth/oauth', oauthRoutes(ctx));
  v1.use('/auth', authRoutes(ctx));
  v1.use('/auth', emailRoutes(ctx));
  v1.use('/me', meRoutes(ctx));
  v1.use('/admin', adminRoutes(ctx));
  app.use('/v1', v1);

  app.use(notFoundHandler);
  app.use(createErrorHandler(ctx.logger));
  return app;
}
