import { AppError } from '../lib/errors.js';

export function notFoundHandler(req, res) {
  res.status(404).json({ error: { code: 'not_found', message: `Route not found: ${req.method} ${req.path}` } });
}

export function createErrorHandler(logger = console) {
  // Express recognises error handlers by their four-argument signature.

  return (err, req, res, next) => {
    if (err instanceof AppError) {
      if (err.headers) res.set(err.headers);
      const body = { code: err.code, message: err.message };
      if (err.details) body.details = err.details;
      return res.status(err.status).json({ error: body });
    }
    if (err.type === 'entity.parse.failed') {
      return res.status(400).json({ error: { code: 'invalid_json', message: 'Request body is not valid JSON' } });
    }
    if (err.type === 'entity.too.large') {
      return res.status(413).json({ error: { code: 'payload_too_large', message: 'Request body is too large' } });
    }
    const status = Number.isInteger(err.status) && err.status >= 400 && err.status < 500 ? err.status : 500;
    if (status === 500) logger.error(err);
    return res.status(status).json({
      error: {
        code: status === 500 ? 'internal_error' : 'bad_request',
        message: status === 500 ? 'Internal server error' : err.message,
      },
    });
  };
}
