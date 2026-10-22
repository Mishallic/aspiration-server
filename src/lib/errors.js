// Every error response has the shape { error: { code, message, details? } }.
// `code` is stable and machine-readable; `message` is for humans and may change.
export class AppError extends Error {
  constructor(status, code, message, { details, headers } = {}) {
    super(message);
    this.name = 'AppError';
    this.status = status;
    this.code = code;
    this.details = details;
    this.headers = headers;
  }
}

export const badRequest = (code, message, details) => new AppError(400, code, message, { details });
export const unauthorized = (code = 'unauthorized', message = 'Authentication is required') =>
  new AppError(401, code, message);
export const forbidden = (code = 'forbidden', message = 'You do not have access to this resource') =>
  new AppError(403, code, message);
export const notFound = (code = 'not_found', message = 'Not found') => new AppError(404, code, message);
export const conflict = (code, message) => new AppError(409, code, message);
export const tooManyRequests = (code, message, retryAfterSeconds) =>
  new AppError(429, code, message, {
    headers: retryAfterSeconds ? { 'Retry-After': String(retryAfterSeconds) } : undefined,
  });
export const serviceUnavailable = (code, message) => new AppError(503, code, message);
