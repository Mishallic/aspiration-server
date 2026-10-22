import { errorResponse, successResponse } from '../src/helpers';
import { errorHandler, notFound } from '../src/middleware/errorHandler';

const mockRes = () => {
  const res = {};
  res.status = jest.fn(() => res);
  res.json = jest.fn(() => res);
  return res;
};

describe('response helpers', () => {
  test('errorResponse sends the status code it is given', () => {
    const res = mockRes();
    errorResponse({}, res, 'nope', 401);
    expect(res.status).toHaveBeenCalledWith(401);
    expect(res.json).toHaveBeenCalledWith({ code: 401, errorMessage: 'nope', data: null, success: false });
  });

  test('errorResponse defaults to 500', () => {
    const res = mockRes();
    errorResponse({}, res);
    expect(res.status).toHaveBeenCalledWith(500);
  });

  test('successResponse sends the status code it is given', () => {
    const res = mockRes();
    successResponse({}, res, { a: 1 }, 201);
    expect(res.status).toHaveBeenCalledWith(201);
    expect(res.json).toHaveBeenCalledWith({ code: 201, data: { a: 1 }, success: true });
  });
});

describe('errorHandler', () => {
  let consoleError;

  beforeEach(() => {
    consoleError = jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => consoleError.mockRestore());

  test('hides internal error details behind a generic 500', () => {
    const res = mockRes();
    errorHandler(new Error('SQLITE_ERROR: no such table: user'), {}, res, () => {});
    expect(res.status).toHaveBeenCalledWith(500);
    expect(res.json.mock.calls[0][0].errorMessage).toBe('Internal server error');
    expect(consoleError).toHaveBeenCalled();
  });

  test('passes through the message of a client error', () => {
    const res = mockRes();
    const err = Object.assign(new Error('Payload too large'), { status: 413 });
    errorHandler(err, {}, res, () => {});
    expect(res.status).toHaveBeenCalledWith(413);
    expect(res.json.mock.calls[0][0].errorMessage).toBe('Payload too large');
    expect(consoleError).not.toHaveBeenCalled();
  });

  test('notFound names the missing route', () => {
    const res = mockRes();
    notFound({ method: 'DELETE', originalUrl: '/x' }, res);
    expect(res.status).toHaveBeenCalledWith(404);
    expect(res.json.mock.calls[0][0].errorMessage).toBe('Route not found: DELETE /x');
  });
});
