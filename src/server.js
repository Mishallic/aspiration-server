import { loadConfig } from './config.js';
import { createContext } from './context.js';
import { createApp } from './app.js';

const HOUR = 3_600_000;

function loadEnvFile() {
  try {
    process.loadEnvFile();
  } catch (err) {
    if (err.code !== 'ENOENT') throw err;
  }
}

async function main() {
  loadEnvFile();
  const config = loadConfig();
  const ctx = await createContext(config);
  const app = createApp(ctx);

  const server = app.listen(config.port, () => {
    const db = ctx.sequelize.getDialect();
    console.log(`Auth server listening on ${config.publicUrl} (port ${config.port}, ${db})`);
    if (db === 'sqlite' && config.isProduction) {
      console.warn('Using SQLite in production. Fine for one instance; use Postgres to scale out.');
    }
  });

  const prune = setInterval(() => {
    Promise.all([ctx.services.sessions.pruneExpired(), ctx.services.oneTimeTokens.pruneExpired()]).catch((err) =>
      console.error('Pruning expired tokens failed:', err.message),
    );
  }, HOUR);
  prune.unref();

  let stopping = false;
  const shutdown = (signal) => {
    if (stopping) return;
    stopping = true;
    console.log(`${signal} received, shutting down`);
    clearInterval(prune);
    server.close(async () => {
      await ctx.close();
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
