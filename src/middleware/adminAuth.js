import { errorResponse } from '../helpers';

const adminAuth = (req, res, next) => {
  if (req.user && req.user.isAdmin) return next();
  return errorResponse(req, res, 'Admin access is required', 403);
};

export default adminAuth;
