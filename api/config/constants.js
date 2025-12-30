// Application constants
export const APP_CONSTANTS = {
  APP_NAME: 'Ravan System',
  APP_VERSION: '4.0.0',
  APP_DESCRIPTION: 'Universal Proxy API with RBAC',
  
  // Roles
  ROLES: {
    OWNER: 'owner',
    ADMIN: 'admin',
    USER: 'user',
    API_USER: 'api_user'
  },
  
  // Batch permissions
  BATCH_PERMISSIONS: {
    ALL: 'all',
    NONE: 'none'
  },
  
  // Cache TTLs (in seconds)
  CACHE_TTL: {
    SHORT: 30,      // 30 seconds
    MEDIUM: 60,     // 1 minute
    LONG: 300,      // 5 minutes
    VERY_LONG: 1800, // 30 minutes
    USER_DATA: 600,  // 10 minutes
    BATCH_DATA: 300  // 5 minutes
  },
  
  // Rate limits
  RATE_LIMITS: {
    AUTH: 10,       // 10 attempts per 15 minutes
    USER: 100,      // 100 requests per 15 minutes
    ADMIN: 500,     // 500 requests per 15 minutes
    API_KEY: 1000,  // 1000 requests per 15 minutes
    PROXY: 100      // 100 proxy requests per 15 minutes
  },
  
  // API timeout (in milliseconds)
  TIMEOUTS: {
    PROXY: 10000,    // 10 seconds
    DATABASE: 5000,  // 5 seconds
    REQUEST: 30000   // 30 seconds
  },
  
  // Pagination defaults
  PAGINATION: {
    DEFAULT_LIMIT: 50,
    MAX_LIMIT: 200,
    DEFAULT_PAGE: 1
  },
  
  // Token expiry
  TOKEN_EXPIRY: {
    ACCESS: '7d',      // 7 days
    REFRESH: '30d',    // 30 days
    API_KEY: '90d'     // 90 days
  },
  
  // Device management
  MAX_DEVICES_PER_USER: 5,
  DEVICE_TOKEN_LENGTH: 64,
  
  // User account defaults
  USER_DEFAULTS: {
    EXPIRY_DAYS: 30,
    ALLOWED_BATCHES: [],
    MAX_LOGIN_ATTEMPTS: 5
  }
};

// HTTP status codes
export const HTTP_STATUS = {
  OK: 200,
  CREATED: 201,
  ACCEPTED: 202,
  NO_CONTENT: 204,
  BAD_REQUEST: 400,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  NOT_FOUND: 404,
  METHOD_NOT_ALLOWED: 405,
  CONFLICT: 409,
  TOO_MANY_REQUESTS: 429,
  INTERNAL_SERVER_ERROR: 500,
  BAD_GATEWAY: 502,
  SERVICE_UNAVAILABLE: 503,
  GATEWAY_TIMEOUT: 504
};

// API response messages
export const API_MESSAGES = {
  SUCCESS: 'Operation successful',
  CREATED: 'Resource created successfully',
  UPDATED: 'Resource updated successfully',
  DELETED: 'Resource deleted successfully',
  LOGGED_IN: 'Logged in successfully',
  LOGGED_OUT: 'Logged out successfully',
  INVALID_CREDENTIALS: 'Invalid username or password',
  ACCESS_DENIED: 'Access denied',
  NOT_FOUND: 'Resource not found',
  ALREADY_EXISTS: 'Resource already exists',
  VALIDATION_ERROR: 'Validation failed',
  TOKEN_EXPIRED: 'Token has expired',
  TOKEN_INVALID: 'Token is invalid',
  RATE_LIMITED: 'Too many requests',
  BATCH_NO_PERMISSION: 'No permission for this batch',
  ACCOUNT_EXPIRED: 'Account has expired',
  DEVICE_LIMIT_REACHED: 'Device limit reached'
};

// Logging levels
export const LOG_LEVELS = {
  ERROR: 'error',
  WARN: 'warn',
  INFO: 'info',
  DEBUG: 'debug',
  TRACE: 'trace'
};

// Export all constants
export default {
  ...APP_CONSTANTS,
  HTTP_STATUS,
  API_MESSAGES,
  LOG_LEVELS
};