// Not Found handler
export function notFoundHandler(req, res) {
  res.status(404).json({
    error: 'Not Found',
    message: `Route ${req.method} ${req.originalUrl} not found`,
    availableRoutes: {
      auth: ['POST /auth/login', 'GET /auth/devices', 'POST /auth/logout-device'],
      owner: ['GET /owner/admins', 'POST /owner/admins', 'DELETE /owner/admins/:username', 'GET /owner/all-users'],
      admin: ['GET /admin/users', 'POST /admin/users', 'PUT /admin/users/:username', 'DELETE /admin/users/:username', 'GET /admin/user-devices/:username'],
      proxy: [
        '/selectionway/*',
        '/rwawebfree/*',
        '/spidyrwa/*',
        '/kgs/*',
        '/Utkarsh/*',
        '/khansir/*',
        '/careerwill/*',
        '/CwVideo/*'
      ]
    },
    docs: '/docs',
    timestamp: new Date().toISOString()
  });
}

// Error handler
export function errorHandler(err, req, res, next) {
  console.error('❌ Error:', {
    message: err.message,
    stack: process.env.NODE_ENV === 'development' ? err.stack : undefined,
    path: req.path,
    method: req.method,
    ip: req.ip,
    user: req.user?.username || 'anonymous',
    timestamp: new Date().toISOString()
  });

  // Mongoose validation error
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      error: 'Validation Error',
      message: err.message,
      details: Object.values(err.errors).map(e => ({
        field: e.path,
        message: e.message
      })),
      timestamp: new Date().toISOString()
    });
  }

  // Mongoose duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyPattern)[0];
    return res.status(409).json({
      error: 'Duplicate Entry',
      message: `${field} already exists`,
      field,
      value: err.keyValue[field],
      timestamp: new Date().toISOString()
    });
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    return res.status(401).json({
      error: 'Invalid Token',
      message: 'Authentication token is invalid',
      timestamp: new Date().toISOString()
    });
  }

  if (err.name === 'TokenExpiredError') {
    return res.status(401).json({
      error: 'Token Expired',
      message: 'Authentication token has expired',
      timestamp: new Date().toISOString()
    });
  }

  // Axios/proxy errors
  if (err.isAxiosError) {
    const status = err.response?.status || 502;
    return res.status(status).json({
      error: 'Proxy Error',
      message: err.response?.data?.message || err.message,
      externalApi: err.config?.url,
      status: err.response?.status,
      timestamp: new Date().toISOString()
    });
  }

  // Custom application errors
  if (err.status && err.message) {
    return res.status(err.status).json({
      error: err.name || 'Application Error',
      message: err.message,
      ...(err.details && { details: err.details }),
      timestamp: new Date().toISOString()
    });
  }

  // Default server error
  res.status(500).json({
    error: 'Internal Server Error',
    message: process.env.NODE_ENV === 'development' ? err.message : 'Something went wrong',
    requestId: req.id,
    timestamp: new Date().toISOString()
  });
}

// Async error wrapper for routes
export function asyncHandler(fn) {
  return (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

// Request validation error
export class ValidationError extends Error {
  constructor(message, details = {}) {
    super(message);
    this.name = 'ValidationError';
    this.status = 400;
    this.details = details;
  }
}

// Authentication error
export class AuthenticationError extends Error {
  constructor(message = 'Authentication required') {
    super(message);
    this.name = 'AuthenticationError';
    this.status = 401;
  }
}

// Authorization error
export class AuthorizationError extends Error {
  constructor(message = 'Insufficient permissions') {
    super(message);
    this.name = 'AuthorizationError';
    this.status = 403;
  }
}

// Not Found error
export class NotFoundError extends Error {
  constructor(resource = 'Resource') {
    super(`${resource} not found`);
    this.name = 'NotFoundError';
    this.status = 404;
  }
}

// Rate limit error
export class RateLimitError extends Error {
  constructor(message = 'Rate limit exceeded') {
    super(message);
    this.name = 'RateLimitError';
    this.status = 429;
  }
}

// Export all error classes
export default {
  notFoundHandler,
  errorHandler,
  asyncHandler,
  ValidationError,
  AuthenticationError,
  AuthorizationError,
  NotFoundError,
  RateLimitError
};