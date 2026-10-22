import { errorResponse } from '../helpers';

export const notFound = (req, res) =>
  errorResponse(req, res, `Route not found: ${req.method} ${req.originalUrl}`, 404);

// Express recognises error handlers by their four-argument signature.
// eslint-disable-next-line no-unused-vars
export const errorHandler = (err, req, res, next) => {
  if (err.type === 'entity.parse.failed') {
    return errorResponse(req, res, 'Request body is not valid JSON', 400);
  }
  const status = err.status || err.statusCode || 500;
  if (status >= 500) console.error(err);
  const message = status >= 500 ? 'Internal server error' : err.message;
  return errorResponse(req, res, message, status);
};
