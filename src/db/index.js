import fs from 'node:fs';
import path from 'node:path';
import { Sequelize } from 'sequelize';
import { Umzug, SequelizeStorage } from 'umzug';
import { defineModels } from './models.js';
import { migrations } from './migrations/index.js';

function createSequelize(databaseUrl) {
  const options = { logging: false };
  if (databaseUrl.startsWith('sqlite:')) {
    const storage = databaseUrl.slice('sqlite:'.length) || ':memory:';
    if (storage !== ':memory:') fs.mkdirSync(path.dirname(path.resolve(storage)), { recursive: true });
    return new Sequelize({ ...options, dialect: 'sqlite', storage });
  }
  if (/^postgres(ql)?:\/\//.test(databaseUrl)) {
    return new Sequelize(databaseUrl, { ...options, dialect: 'postgres' });
  }
  throw new Error('DATABASE_URL must start with postgres://, postgresql:// or sqlite:');
}

export function createDb(config) {
  const sequelize = createSequelize(config.databaseUrl);
  const models = defineModels(sequelize);

  const migrator = new Umzug({
    migrations: migrations.map(({ name, up, down }) => ({
      name,
      up: () => up({ queryInterface: sequelize.getQueryInterface(), Sequelize }),
      down: () => down({ queryInterface: sequelize.getQueryInterface(), Sequelize }),
    })),
    storage: new SequelizeStorage({ sequelize, tableName: 'schema_migrations' }),
    logger: undefined,
  });

  return {
    sequelize,
    models,
    migrate: () => migrator.up(),
    close: () => sequelize.close(),
  };
}
