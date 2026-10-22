import { rateLimit, ipKeyGenerator } from 'express-rate-limit';
import { tooManyRequests } from '../lib/errors.js';

const MINUTE = 60_000;

// In-memory counters: correct for one instance. Behind several instances, put a shared
// store (for example Redis) in place, or rate-limit at the proxy.
export function createRateLimits(config) {
  const make = (options) => {
    if (!config.rateLimitEnabled) return (req, res, next) => next();
    return rateLimit({
      standardHeaders: 'draft-8',
      legacyHeaders: false,
      handler: (req, res, next, opts) =>
        next(tooManyRequests('rate_limited', 'Too many requests, try again later', Math.ceil(opts.windowMs / 1000))),
      ...options,
    });
  };

  const emailKey = (req) => {
    const email = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    return `email:${email || ipKeyGenerator(req.ip)}`;
  };

  return {
    // Every /v1 request.
    api: make({ windowMs: 15 * MINUTE, limit: 1000 }),
    // Password and identity-token sign-in, sign-up: slows credential stuffing.
    credentials: make({ windowMs: 15 * MINUTE, limit: 30 }),
    refresh: make({ windowMs: 15 * MINUTE, limit: 200 }),
    // Endpoints that send email: per IP, and per address so nobody can flood one inbox.
    emailPerIp: make({ windowMs: 60 * MINUTE, limit: 20 }),
    emailPerAddress: make({ windowMs: 60 * MINUTE, limit: 5, keyGenerator: emailKey }),
    // Token-in-link endpoints: stops guessing, although 256-bit tokens make that hopeless anyway.
    tokenUse: make({ windowMs: 15 * MINUTE, limit: 50 }),
  };
}
