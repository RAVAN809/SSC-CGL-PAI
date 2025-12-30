import rateLimit from 'express-rate-limit';

// Default rate limiter
export function createRateLimiter(options = {}) {
  return rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
    max: parseInt(process.env.RATE_LIMIT_MAX) || 100, // Limit each IP to 100 requests per windowMs
    message: {
      error: 'Too many requests',
      message: 'Please try again later.',
      retryAfter: '15 minutes'
    },
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
    skipSuccessfulRequests: process.env.RATE_LIMIT_SKIP_SUCCESSFUL === 'true',
    skip: (req) => {
      // Skip rate limiting for internal health checks
      if (req.path === '/health' || req.path === '/') {
        return true;
      }
      
      // Skip for API keys with higher limits
      if (req.headers['x-api-key'] && process.env.API_KEY_SKIP_RATE_LIMIT === 'true') {
        return true;
      }
      
      return false;
    },
    ...options
  });
}

// Stricter rate limiter for authentication endpoints
export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 login attempts per IP per 15 minutes
  message: {
    error: 'Too many login attempts',
    message: 'Please try again after 15 minutes.'
  },
  skipSuccessfulRequests: true // Only count failed attempts
});

// API-specific rate limiters
export const proxyRateLimiter = rateLimit({
  windowMs: parseInt(process.env.PROXY_RATE_WINDOW) || 15 * 60 * 1000,
  max: parseInt(process.env.PROXY_RATE_LIMIT) || 100,
  keyGenerator: (req) => {
    // Use API key if available, otherwise use IP
    return req.headers['x-api-key'] || req.ip;
  },
  message: {
    error: 'Proxy rate limit exceeded',
    message: 'Too many requests to external APIs'
  }
});

// Batch-specific rate limiter
export function createBatchRateLimiter(batchId) {
  return rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes per batch
    max: 30, // 30 requests per batch per 5 minutes
    keyGenerator: (req) => `${req.ip}:${batchId}`,
    message: {
      error: 'Batch rate limit exceeded',
      batchId,
      message: 'Too many requests for this batch'
    }
  });
}

// User-specific rate limiter
export function createUserRateLimiter(userId) {
  return rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 500, // 500 requests per user per hour
    keyGenerator: () => userId,
    message: {
      error: 'User rate limit exceeded',
      message: 'You have exceeded your hourly request limit'
    }
  });
}

// Admin/owner rate limiter (higher limits)
export const adminRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 500, // Higher limit for admins
  skip: (req) => {
    // Skip rate limiting for owners
    return req.user?.role === 'owner';
  },
  message: {
    error: 'Rate limit exceeded',
    message: 'Admin rate limit reached'
  }
});

// Export all limiters
export default {
  createRateLimiter,
  authLimiter,
  proxyRateLimiter,
  createBatchRateLimiter,
  createUserRateLimiter,
  adminRateLimiter
};