import { DataTypes } from 'sequelize';

// Column definitions must stay in step with the migrations in ./migrations.
export function defineModels(sequelize) {
  const User = sequelize.define(
    'User',
    {
      id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
      email: { type: DataTypes.STRING(320), allowNull: false, unique: true },
      emailVerifiedAt: { type: DataTypes.DATE, allowNull: true },
      passwordHash: { type: DataTypes.STRING(255), allowNull: true },
      firstName: { type: DataTypes.STRING(100), allowNull: true },
      lastName: { type: DataTypes.STRING(100), allowNull: true },
      avatarUrl: { type: DataTypes.STRING(2048), allowNull: true },
      role: { type: DataTypes.STRING(20), allowNull: false, defaultValue: 'user' },
      failedLoginCount: { type: DataTypes.INTEGER, allowNull: false, defaultValue: 0 },
      lockedUntil: { type: DataTypes.DATE, allowNull: true },
      tokensValidAfter: { type: DataTypes.DATE, allowNull: true },
    },
    { tableName: 'users' },
  );

  const Identity = sequelize.define(
    'Identity',
    {
      id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
      userId: { type: DataTypes.UUID, allowNull: false },
      provider: { type: DataTypes.STRING(20), allowNull: false },
      providerUserId: { type: DataTypes.STRING(255), allowNull: false },
      email: { type: DataTypes.STRING(320), allowNull: true },
    },
    { tableName: 'identities' },
  );

  const RefreshToken = sequelize.define(
    'RefreshToken',
    {
      id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
      userId: { type: DataTypes.UUID, allowNull: false },
      familyId: { type: DataTypes.UUID, allowNull: false },
      tokenHash: { type: DataTypes.STRING(64), allowNull: false, unique: true },
      expiresAt: { type: DataTypes.DATE, allowNull: false },
      revokedAt: { type: DataTypes.DATE, allowNull: true },
      userAgent: { type: DataTypes.STRING(255), allowNull: true },
      ip: { type: DataTypes.STRING(64), allowNull: true },
    },
    { tableName: 'refresh_tokens', updatedAt: false },
  );

  const OneTimeToken = sequelize.define(
    'OneTimeToken',
    {
      id: { type: DataTypes.UUID, defaultValue: DataTypes.UUIDV4, primaryKey: true },
      userId: { type: DataTypes.UUID, allowNull: true },
      purpose: { type: DataTypes.STRING(30), allowNull: false },
      tokenHash: { type: DataTypes.STRING(64), allowNull: false, unique: true },
      data: { type: DataTypes.JSON, allowNull: true },
      expiresAt: { type: DataTypes.DATE, allowNull: false },
      usedAt: { type: DataTypes.DATE, allowNull: true },
    },
    { tableName: 'one_time_tokens', updatedAt: false },
  );

  const SigningKey = sequelize.define(
    'SigningKey',
    {
      kid: { type: DataTypes.STRING(64), primaryKey: true },
      alg: { type: DataTypes.STRING(10), allowNull: false },
      publicJwk: { type: DataTypes.JSON, allowNull: false },
      privateJwk: { type: DataTypes.JSON, allowNull: false },
      active: { type: DataTypes.BOOLEAN, allowNull: false, defaultValue: false },
      retiredAt: { type: DataTypes.DATE, allowNull: true },
    },
    { tableName: 'signing_keys', updatedAt: false },
  );

  const cascade = { foreignKey: 'userId', onDelete: 'CASCADE' };
  User.hasMany(Identity, cascade);
  Identity.belongsTo(User, { foreignKey: 'userId' });
  User.hasMany(RefreshToken, cascade);
  RefreshToken.belongsTo(User, { foreignKey: 'userId' });
  User.hasMany(OneTimeToken, cascade);

  return { User, Identity, RefreshToken, OneTimeToken, SigningKey };
}
