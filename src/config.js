require('dotenv').config();

const env = process.env.NODE_ENV || 'development';

const config = {
  env,
  port: Number(process.env.PORT) || 8080,
  jwtSecret: process.env.SECRET || (env === 'production' ? undefined : 'dev-only-insecure-secret'),
  jwtExpiresIn: process.env.JWT_EXPIRES_IN || '7d',
  bcryptRounds: Number(process.env.BCRYPT_ROUNDS) || (env === 'test' ? 4 : 10),
  corsOrigin: process.env.CORS_ORIGIN || '*',
  db: {
    url: process.env.DB_CONNECTION_STRING,
    dialect: process.env.DB_DIALECT || 'sqlite',
    storage: process.env.DB_STORAGE || './dev.sqlite',
    name: process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT ? Number(process.env.DB_PORT) : undefined,
  },
  google: {
    clientId: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackUrl: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:8080/oauth/google/callback',
    clientRedirect: process.env.CLIENT_OAUTH_REDIRECT,
  },
};

if (!config.jwtSecret) {
  throw new Error('SECRET must be set when NODE_ENV=production');
}

module.exports = config;
