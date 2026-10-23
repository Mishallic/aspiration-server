const timestamps = (Sequelize, { updated = true } = {}) => ({
  createdAt: { type: Sequelize.DATE, allowNull: false },
  ...(updated ? { updatedAt: { type: Sequelize.DATE, allowNull: false } } : {}),
});

const userFk = (Sequelize, allowNull = false) => ({
  type: Sequelize.UUID,
  allowNull,
  references: { model: 'users', key: 'id' },
  onDelete: 'CASCADE',
});

export async function up({ queryInterface, Sequelize }) {
  await queryInterface.createTable('users', {
    id: { type: Sequelize.UUID, primaryKey: true },
    email: { type: Sequelize.STRING(320), allowNull: false, unique: true },
    emailVerifiedAt: { type: Sequelize.DATE, allowNull: true },
    passwordHash: { type: Sequelize.STRING(255), allowNull: true },
    firstName: { type: Sequelize.STRING(100), allowNull: true },
    lastName: { type: Sequelize.STRING(100), allowNull: true },
    avatarUrl: { type: Sequelize.STRING(2048), allowNull: true },
    role: { type: Sequelize.STRING(20), allowNull: false, defaultValue: 'user' },
    failedLoginCount: { type: Sequelize.INTEGER, allowNull: false, defaultValue: 0 },
    lockedUntil: { type: Sequelize.DATE, allowNull: true },
    tokensValidAfter: { type: Sequelize.DATE, allowNull: true },
    ...timestamps(Sequelize),
  });

  await queryInterface.createTable('identities', {
    id: { type: Sequelize.UUID, primaryKey: true },
    userId: userFk(Sequelize),
    provider: { type: Sequelize.STRING(20), allowNull: false },
    providerUserId: { type: Sequelize.STRING(255), allowNull: false },
    email: { type: Sequelize.STRING(320), allowNull: true },
    ...timestamps(Sequelize),
  });
  await queryInterface.addIndex('identities', ['provider', 'providerUserId'], { unique: true });
  await queryInterface.addIndex('identities', ['userId']);

  await queryInterface.createTable('refresh_tokens', {
    id: { type: Sequelize.UUID, primaryKey: true },
    userId: userFk(Sequelize),
    familyId: { type: Sequelize.UUID, allowNull: false },
    tokenHash: { type: Sequelize.STRING(64), allowNull: false, unique: true },
    expiresAt: { type: Sequelize.DATE, allowNull: false },
    revokedAt: { type: Sequelize.DATE, allowNull: true },
    userAgent: { type: Sequelize.STRING(255), allowNull: true },
    ip: { type: Sequelize.STRING(64), allowNull: true },
    ...timestamps(Sequelize, { updated: false }),
  });
  await queryInterface.addIndex('refresh_tokens', ['userId']);
  await queryInterface.addIndex('refresh_tokens', ['familyId']);

  await queryInterface.createTable('one_time_tokens', {
    id: { type: Sequelize.UUID, primaryKey: true },
    userId: userFk(Sequelize, true),
    purpose: { type: Sequelize.STRING(30), allowNull: false },
    tokenHash: { type: Sequelize.STRING(64), allowNull: false, unique: true },
    data: { type: Sequelize.JSON, allowNull: true },
    expiresAt: { type: Sequelize.DATE, allowNull: false },
    usedAt: { type: Sequelize.DATE, allowNull: true },
    ...timestamps(Sequelize, { updated: false }),
  });
  await queryInterface.addIndex('one_time_tokens', ['userId', 'purpose']);

  await queryInterface.createTable('signing_keys', {
    kid: { type: Sequelize.STRING(64), primaryKey: true },
    alg: { type: Sequelize.STRING(10), allowNull: false },
    publicJwk: { type: Sequelize.JSON, allowNull: false },
    privateJwk: { type: Sequelize.JSON, allowNull: false },
    active: { type: Sequelize.BOOLEAN, allowNull: false, defaultValue: false },
    retiredAt: { type: Sequelize.DATE, allowNull: true },
    ...timestamps(Sequelize, { updated: false }),
  });
}

export async function down({ queryInterface }) {
  for (const table of ['signing_keys', 'one_time_tokens', 'refresh_tokens', 'identities', 'users']) {
    await queryInterface.dropTable(table);
  }
}
