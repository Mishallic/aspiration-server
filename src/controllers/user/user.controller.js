import {User} from '../../models';
import {successResponse, errorResponse, uniqueId} from '../../helpers';
import crypto from "crypto";
import jwt from "jsonwebtoken"

export const allUsers = async (req, res) => {
    try {
        const page = req.params.page || 1;
        const limit = 2;
        const users = await User.findAndCountAll({
            order: [['createdAt', 'DESC'], ['firstName', 'ASC']],
            offset: (page - 1) * limit,
            limit,
        });
        return res.send({code: 200, data: users, success: true})
    } catch (error) {
        return res.status(500).json({
            code: 500,
            message: error.message,
            data: null,
            success: false
        })
    }
};

export const register = async (req, res) => {
    try {
        const {email, password} = req.body;
        if (!email || !password || email.trim() === '' || password.trim() === '')
            throw new Error('Invalid email or password')
        const user = await User.scope('withSecretColumns').findOne({
            where: {email},
        });
        if (user) {
            throw new Error('User already exists with same email');
        }
        const reqPass = crypto
            .createHash('md5')
            .update(password)
            .digest('hex');
        const payload = {
            email,
            password: reqPass,
            isVerified: false,
            verifyToken: uniqueId(),
        };

        const newUser = await User.create(payload);
        return res.send({code: 200, data: {}, success: true, message: 'User created successfully!'})
    } catch (err) {
        return res.status(500).json({
            code: 500,
            message: err.message,
            data: null,
            success: false
        })
    }
}


export const login = async (req, res) => {
    try {
        const user = await User.scope('withSecretColumns').findOne({
            where: {email: req.body.email},
        });

        if (!user) 
            throw new Error('Incorrect Email Id/Password');

        if (user.googleId && user.isVerified)
            return res.redirect(306, '/oauth/google')

        const reqPass = crypto
            .createHash('md5')
            .update(req.body.password || '')
            .digest('hex');
        if (reqPass !== user.password) {
            throw new Error('Incorrect Email Id/Password');
        }
        const token = jwt.sign(
            {
                user: {
                    userId: user.id,
                    email: user.email,
                    createdAt: new Date(),
                },
            },
            process.env.SECRET,
        );
        delete user.dataValues.password;
        return res.send({code: 200, data: {user, token}, success: true})
    } catch (error) {
        return res.status(500).json({
            code: 500,
            message: error.message,
            data: null,
            success: false
        })
    }
};

export const changePassword = async (req, res) => {
    try {
        const { userId } = req.user;
        if (!newPassword || !oldPassword || oldPassword.trim() === '' || newPassword.trim() === '')
            throw new Error('Data Incomplete');
        const user = await User.scope('withSecretColumns').findOne({
            where: {id: userId},
        });

        const reqPass = crypto
            .createHash('md5')
            .update(req.body.oldPassword)
            .digest('hex');
        if (reqPass !== user.password) {
            throw new Error('Old password is incorrect');
        }

        const newPass = crypto
            .createHash('md5')
            .update(req.body.newPassword)
            .digest('hex');

        await User.update({password: newPass}, {where: {id: user.id}});
        return res.send({code: 200, data: {}, success: true})
    } catch (error) {
        return res.status(500).json({
            code: 500,
            message: error.message,
            data: null,
            success: false
        })
    }
};

export const me = async (req, res) => {
    try {
        const {id} = req.body
        const {googleId} = req.body
        let whereQ = {googleId: googleId};
        if (id)
            whereQ = {id: id}
        const user = await User.findOne({
            where: whereQ
        })
        if (!user)
            throw new Error('Invalid');

        const token = jwt.sign(
            {
                user: {
                    userId: user.id,
                    email: user.email,
                    createdAt: new Date(),
                },
            },
            process.env.SECRET,
        );
        delete user.dataValues.password;
        return res.send({code: 200, data: {user, token}, success: true})
    } catch (err) {
        return res.status(500).json({
            code: 500,
            message: err.message,
            data: null,
            success: false
        })
    }
}

export const oauthLog = async (data) => {
    try {
        let user = await User.findOne({
            where: {
                googleId: data.id,
                email: data._json.email,
            }
        })
        if (!user) {
            let payload = {
                firstName: data.name.givenName,
                lastName: data.name.familyName,
                email: data._json.email,
                isVerified: Number(data._json.email_verified).toString(),
                profilePhoto: data._json.picture,
                password: uniqueId(),
                googleId: data.id
            }
            user = await User.create(payload);
        }
        return user;
    } catch (e) {
        console.log('HERROR: ', e);
    }
}
