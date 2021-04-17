module.exports = (sequelize, DataTypes) => {
    const User = sequelize.define(
        'User',
        {
            firstName: {
                type: DataTypes.STRING,
            },
            lastName: {
                type: DataTypes.STRING,
            },
            email: {
                type: DataTypes.STRING,
                allowNull: false,
                unique: true,
            },
            password: {
                type: DataTypes.STRING,
                allowNull: false
            },
            profilePhoto: {
                type: DataTypes.STRING,
            },
            isAdmin: {
                type: DataTypes.BOOLEAN,
                defaultValue: false,
            },
            verifyToken: {
                type: DataTypes.STRING,
                defaultValue: null
            },
            isVerified: {
                type: DataTypes.BOOLEAN,
                defaultValue: false
            }
        },
        {
            defaultScope: {
                attributes: {exclude: ['password', 'verifyToken', 'isAdmin']},
            },
            scopes: {
                withSecretColumns: {
                    attributes: {include: ['password', 'verifyToken', 'isAdmin']},
                },
            },
            tableName: 'user'
        }
    )
    User.associate = function (models) {

    }
    return User;
}