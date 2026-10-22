'use strict';

const fs = require('fs');
const path = require('path');
const Sequelize = require('sequelize');
const config = require('../config');

const basename = path.basename(__filename);
const db = {};

function createSequelize() {
  const { db: dbConfig, env } = config;
  const options = { logging: false };

  // Tests always run against a throwaway in-memory database.
  if (env === 'test') {
    return new Sequelize({ ...options, dialect: 'sqlite', storage: ':memory:' });
  }
  if (dbConfig.url) {
    return new Sequelize(dbConfig.url, { ...options, dialect: dbConfig.dialect });
  }
  if (dbConfig.dialect === 'sqlite') {
    return new Sequelize({ ...options, dialect: 'sqlite', storage: dbConfig.storage });
  }
  return new Sequelize(dbConfig.name, dbConfig.user, dbConfig.password, {
    ...options,
    dialect: dbConfig.dialect,
    host: dbConfig.host,
    port: dbConfig.port,
  });
}

const sequelize = createSequelize();

fs.readdirSync(__dirname)
  .filter((file) => file !== basename && !file.startsWith('.') && file.endsWith('.js'))
  .forEach((file) => {
    const model = require(path.join(__dirname, file))(sequelize, Sequelize.DataTypes);
    db[model.name] = model;
  });

Object.keys(db).forEach((name) => {
  if (db[name].associate) db[name].associate(db);
});

db.sequelize = sequelize;
db.Sequelize = Sequelize;

module.exports = db;
