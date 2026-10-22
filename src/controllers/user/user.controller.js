import { User } from '../../models';
import {
  successResponse,
  errorResponse,
  uniqueId,
  hashPassword,
  comparePassword,
  signToken,
  publicUser,
  isEmail,
  isNonEmptyString,
  MIN_PASSWORD_LENGTH,
} from '../../helpers';

const MAX_PAGE_SIZE = 100;
const DEFAULT_PAGE_SIZE = 20;

const toPositiveInt = (value, fallback) => {
  const n = Number.parseInt(value, 10);
  return Number.isInteger(n) && n > 0 ? n : fallback;
};

export const register = async (req, res, next) => {
  try {
    const { email, password, firstName, lastName } = req.body || {};
    if (!isNonEmptyString(email) || !isNonEmptyString(password)) {
      return errorResponse(req, res, 'Email and password are required', 400);
    }
    if (!isEmail(email)) return errorResponse(req, res, 'Email is not valid', 400);
    if (password.length < MIN_PASSWORD_LENGTH) {
      return errorResponse(req, res, `Password must be at least ${MIN_PASSWORD_LENGTH} characters`, 400);
    }

    const normalizedEmail = email.trim().toLowerCase();
    const existing = await User.findOne({ where: { email: normalizedEmail } });
    if (existing) return errorResponse(req, res, 'User already exists with same email', 409);

    const user = await User.create({
      email: normalizedEmail,
      firstName,
      lastName,
      password: await hashPassword(password),
      isVerified: false,
      verifyToken: uniqueId(),
    });
    return successResponse(req, res, { user: publicUser(user) }, 201);
  } catch (err) {
    return next(err);
  }
};

export const login = async (req, res, next) => {
  try {
    const { email, password } = req.body || {};
    if (!isNonEmptyString(email) || !isNonEmptyString(password)) {
      return errorResponse(req, res, 'Email and password are required', 400);
    }

    const user = await User.scope('withSecretColumns').findOne({
      where: { email: email.trim().toLowerCase() },
    });
    // Same message for an unknown email and a wrong password, so the
    // endpoint cannot be used to discover which emails are registered.
    if (!user || !(await comparePassword(password, user.password))) {
      return errorResponse(req, res, 'Incorrect email or password', 401);
    }

    return successResponse(req, res, { user: publicUser(user), token: signToken(user) });
  } catch (err) {
    return next(err);
  }
};

export const me = async (req, res, next) => {
  try {
    const user = await User.findByPk(req.user.userId);
    if (!user) return errorResponse(req, res, 'User is not found in system', 404);
    return successResponse(req, res, { user: publicUser(user) });
  } catch (err) {
    return next(err);
  }
};

export const changePassword = async (req, res, next) => {
  try {
    const { oldPassword, newPassword } = req.body || {};
    if (!isNonEmptyString(oldPassword) || !isNonEmptyString(newPassword)) {
      return errorResponse(req, res, 'oldPassword and newPassword are required', 400);
    }
    if (newPassword.length < MIN_PASSWORD_LENGTH) {
      return errorResponse(req, res, `New password must be at least ${MIN_PASSWORD_LENGTH} characters`, 400);
    }

    const user = await User.scope('withSecretColumns').findByPk(req.user.userId);
    if (!user || !(await comparePassword(oldPassword, user.password))) {
      return errorResponse(req, res, 'Old password is incorrect', 401);
    }

    await user.update({ password: await hashPassword(newPassword) });
    return successResponse(req, res, {});
  } catch (err) {
    return next(err);
  }
};

export const allUsers = async (req, res, next) => {
  try {
    const page = toPositiveInt(req.query.page, 1);
    const limit = Math.min(toPositiveInt(req.query.limit, DEFAULT_PAGE_SIZE), MAX_PAGE_SIZE);
    const { count, rows } = await User.findAndCountAll({
      order: [['createdAt', 'DESC'], ['id', 'DESC']],
      offset: (page - 1) * limit,
      limit,
    });
    return successResponse(req, res, {
      users: rows.map(publicUser),
      page,
      limit,
      total: count,
      totalPages: Math.ceil(count / limit),
    });
  } catch (err) {
    return next(err);
  }
};

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
