import { errorResponse, verifyToken } from '../helpers';
import { User } from '../models';

const apiAuth = async (req, res, next) => {
  const token = req.headers['x-token'];
  if (!token) return errorResponse(req, res, 'Token is not provided', 401);

  let decoded;
  try {
    decoded = verifyToken(token);
  } catch (err) {
    return errorResponse(req, res, 'Invalid or expired token, please log in again', 401);
  }

  try {
    const user = await User.scope('withSecretColumns').findByPk(decoded.user.userId);
    if (!user) return errorResponse(req, res, 'User is not found in system', 401);

    const reqUser = user.get({ plain: true });
    delete reqUser.password;
    delete reqUser.verifyToken;
    reqUser.userId = user.id;
    req.user = reqUser;
    return next();
  } catch (err) {
    return next(err);
  }
};

export default apiAuth;
