require('@babel/register');

const config = require('./src/config');
const app = require('./src/app');
const { sequelize } = require('./src/models');

async function start() {
  try {
    await sequelize.authenticate();
    await sequelize.sync();
    app.listen(config.port, () => {
      console.log(`aspiration-server listening on http://localhost:${config.port} (${sequelize.getDialect()})`);
    });
  } catch (err) {
    console.error('Failed to start:', err.message);
    process.exit(1);
  }
}

start();
