import { createDb } from './db/index.js';
import { createKeyStore } from './services/keys.js';
import { createSessionService } from './services/sessions.js';
import { createOneTimeTokenService } from './services/oneTimeTokens.js';
import { createMailer } from './services/mailer.js';
import { createWebhooks } from './services/webhooks.js';
import { createEmailFlows } from './services/emailFlows.js';
import { createAccountService } from './services/accounts.js';
import { createOAuthProviders } from './services/oauthProviders.js';

// Builds everything the app needs: database (migrated), keys and services.
// Route modules receive this context instead of importing globals.
export async function createContext(config, { logger = console, fetchImpl } = {}) {
  const db = createDb(config);
  await db.migrate();

  const keys = createKeyStore({ config, sequelize: db.sequelize, models: db.models });
  await keys.load();

  const services = {
    keys,
    sessions: createSessionService({ config, models: db.models, keys }),
    oneTimeTokens: createOneTimeTokenService({ models: db.models }),
    mailer: createMailer({ config, logger }),
    webhooks: createWebhooks({ config, logger, fetchImpl }),
  };
  services.emailFlows = createEmailFlows({ config, models: db.models, services });
  services.accounts = createAccountService({ sequelize: db.sequelize, models: db.models, services });
  services.oauthProviders = createOAuthProviders({ config, fetchImpl: fetchImpl ?? globalThis.fetch });

  return {
    config,
    logger,
    sequelize: db.sequelize,
    models: db.models,
    services,
    fetchImpl: fetchImpl ?? globalThis.fetch,
    async close() {
      await services.webhooks.flush();
      await db.close();
    },
  };
}
