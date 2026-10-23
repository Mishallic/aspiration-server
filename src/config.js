import { z } from 'zod';

const list = z
  .string()
  .optional()
  .transform((value) => (value ? value.split(',').map((item) => item.trim()).filter(Boolean) : []));

const flag = (fallback) =>
  z
    .enum(['true', 'false', '1', '0'])
    .optional()
    .transform((value) => (value === undefined ? fallback : value === 'true' || value === '1'));

const optionalString = z
  .string()
  .optional()
  .transform((value) => (value && value.trim() ? value.trim() : undefined));

const schema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  PORT: z.coerce.number().int().min(1).max(65535).default(8080),
  PUBLIC_URL: z.url().default('http://localhost:8080'),
  DATABASE_URL: optionalString,
  TRUST_PROXY: optionalString,
  CORS_ORIGINS: list,
  ALLOWED_REDIRECT_URLS: list,
  APP_NAME: z.string().min(1).default('Your app'),

  JWT_AUDIENCE: z.string().min(1).default('app'),
  ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(86400).default(900),
  REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().min(1).max(365).default(30),
  SIGNING_KEY: optionalString,

  REQUIRE_EMAIL_VERIFICATION: flag(false),
  SMTP_URL: optionalString,
  EMAIL_FROM: z.string().min(3).default('Auth <no-reply@localhost>'),
  PASSWORD_RESET_URL: z.url().optional(),
  EMAIL_VERIFIED_REDIRECT_URL: z.url().optional(),

  GOOGLE_CLIENT_ID: optionalString,
  GOOGLE_CLIENT_SECRET: optionalString,
  GOOGLE_NATIVE_CLIENT_IDS: list,
  GITHUB_CLIENT_ID: optionalString,
  GITHUB_CLIENT_SECRET: optionalString,
  APPLE_CLIENT_IDS: list,

  WEBHOOK_URL: z.url().optional(),
  WEBHOOK_SECRET: optionalString,

  RATE_LIMIT_ENABLED: flag(true),
});

function stripTrailingSlash(url) {
  return url.endsWith('/') ? url.slice(0, -1) : url;
}

function isLocalhost(url) {
  const { hostname } = new URL(url);
  return hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '[::1]';
}

export function loadConfig(env = process.env) {
  const parsed = schema.safeParse(env);
  if (!parsed.success) {
    const problems = parsed.error.issues.map((issue) => `  ${issue.path.join('.')}: ${issue.message}`);
    throw new Error(`Invalid configuration:\n${problems.join('\n')}`);
  }
  const e = parsed.data;
  const problems = [];

  if ((e.GOOGLE_CLIENT_ID && !e.GOOGLE_CLIENT_SECRET) || (!e.GOOGLE_CLIENT_ID && e.GOOGLE_CLIENT_SECRET)) {
    problems.push('GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET must be set together');
  }
  if ((e.GITHUB_CLIENT_ID && !e.GITHUB_CLIENT_SECRET) || (!e.GITHUB_CLIENT_ID && e.GITHUB_CLIENT_SECRET)) {
    problems.push('GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be set together');
  }
  if (e.WEBHOOK_URL && (!e.WEBHOOK_SECRET || e.WEBHOOK_SECRET.length < 24)) {
    problems.push('WEBHOOK_SECRET of at least 24 characters is required when WEBHOOK_URL is set');
  }
  for (const url of e.ALLOWED_REDIRECT_URLS) {
    if (!URL.canParse(url)) problems.push(`ALLOWED_REDIRECT_URLS entry is not a URL: ${url}`);
  }
  if (e.NODE_ENV === 'production' && !e.PUBLIC_URL.startsWith('https://') && !isLocalhost(e.PUBLIC_URL)) {
    problems.push('PUBLIC_URL must use https in production');
  }
  if (problems.length) throw new Error(`Invalid configuration:\n${problems.map((p) => `  ${p}`).join('\n')}`);

  const publicUrl = stripTrailingSlash(e.PUBLIC_URL);
  const defaultDatabase = e.NODE_ENV === 'test' ? 'sqlite::memory:' : 'sqlite:./data/auth.sqlite';

  return Object.freeze({
    env: e.NODE_ENV,
    isProduction: e.NODE_ENV === 'production',
    port: e.PORT,
    publicUrl,
    secureCookies: publicUrl.startsWith('https://'),
    databaseUrl: e.DATABASE_URL || defaultDatabase,
    trustProxy: e.TRUST_PROXY,
    corsOrigins: e.CORS_ORIGINS,
    allowedRedirectUrls: e.ALLOWED_REDIRECT_URLS.map(stripTrailingSlash),
    appName: e.APP_NAME,
    jwt: Object.freeze({
      issuer: publicUrl,
      audience: e.JWT_AUDIENCE,
      accessTokenTtlSeconds: e.ACCESS_TOKEN_TTL_SECONDS,
      refreshTokenTtlDays: e.REFRESH_TOKEN_TTL_DAYS,
      signingKeyPem: e.SIGNING_KEY,
    }),
    email: Object.freeze({
      requireVerification: e.REQUIRE_EMAIL_VERIFICATION,
      smtpUrl: e.SMTP_URL,
      from: e.EMAIL_FROM,
      passwordResetUrl: e.PASSWORD_RESET_URL,
      verifiedRedirectUrl: e.EMAIL_VERIFIED_REDIRECT_URL,
    }),
    oauth: Object.freeze({
      google: e.GOOGLE_CLIENT_ID
        ? Object.freeze({ clientId: e.GOOGLE_CLIENT_ID, clientSecret: e.GOOGLE_CLIENT_SECRET })
        : null,
      github: e.GITHUB_CLIENT_ID
        ? Object.freeze({ clientId: e.GITHUB_CLIENT_ID, clientSecret: e.GITHUB_CLIENT_SECRET })
        : null,
      // Only the explicit native/mobile client IDs. The confidential web client ID is
      // deliberately NOT folded in: an ID token minted for the web code flow must not
      // also be accepted at the native endpoint. Add it to GOOGLE_NATIVE_CLIENT_IDS if
      // a browser Google Sign-In genuinely posts its token to /native.
      googleNativeClientIds: Object.freeze([...new Set(e.GOOGLE_NATIVE_CLIENT_IDS)]),
      appleClientIds: Object.freeze(e.APPLE_CLIENT_IDS),
    }),
    webhook: e.WEBHOOK_URL ? Object.freeze({ url: e.WEBHOOK_URL, secret: e.WEBHOOK_SECRET }) : null,
    rateLimitEnabled: e.RATE_LIMIT_ENABLED,
  });
}
