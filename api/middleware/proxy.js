import { getProxyService } from '../services/proxyService.js';
import { requireAuthWithExpiry, requireDynamicBatchPermission } from './auth.js';
import AppCache from '../cache.js';
import AppLogger from '../utils/logger.js';
import { API_ROUTES } from '../config/apis.js';

// Middleware to identify API from route
export function identifyApi(req, res, next) {
  const path = req.originalUrl;
  
  // Find which API this request is for
  for (const [route, apiName] of Object.entries(API_ROUTES)) {
    if (path.startsWith(route)) {
      req.apiName = apiName;
      req.apiRoute = route;
      break;
    }
  }
  
  if (!req.apiName) {
    return res.status(404).json({ 
      error: 'API route not found',
      message: `No proxy configuration found for: ${path}`,
      availableRoutes: Object.entries(API_ROUTES).map(([route, name]) => ({
        route,
        name,
        example: `${route}/batches`
      }))
    });
  }
  
  next();
}

// Middleware to extract batch ID for permission checking
export function extractBatchId(req, res, next) {
  try {
    if (!req.apiName) {
      return next();
    }
    
    const proxyService = getProxyService(req.apiName);
    const batchId = proxyService.extractBatchId(req);
    
    if (batchId) {
      req.batchId = batchId;
      AppLogger.logBatchAccess(
        req.user?.username || 'anonymous',
        batchId,
        true, // Will be checked in permission middleware
        req.path
      );
    }
    
    next();
  } catch (error) {
    console.error('Batch ID extraction error:', error);
    next(); // Continue even if extraction fails
  }
}

// Main proxy handler middleware
export const proxyHandler = [
  identifyApi,
  requireAuthWithExpiry,
  extractBatchId,
  requireDynamicBatchPermission,
  handleProxyRequest
];

async function handleProxyRequest(req, res) {
  try {
    const proxyService = getProxyService(req.apiName);
    
    // Check if authentication is required for this API
    if (proxyService.config.requiresAuth && !req.user) {
      return res.status(401).json({ 
        error: 'Authentication required',
        message: `Authentication is required to access ${proxyService.config.name}`
      });
    }
    
    // Log the proxy request
    AppLogger.debug(`Proxy request: ${req.method} ${req.originalUrl}`, {
      apiName: req.apiName,
      batchId: req.batchId,
      userId: req.user?.username
    });
    
    // Make proxy request
    const startTime = Date.now();
    const result = await proxyService.proxyRequest(req);
    const duration = Date.now() - startTime;
    
    // Log successful proxy
    AppLogger.logProxyRequest(
      req.apiName,
      req.originalUrl,
      result.status || 200,
      duration,
      result.fromCache || false
    );
    
    // Add proxy headers
    res.set({
      'X-Proxy-Server': 'Ravan System',
      'X-Proxied-From': proxyService.config.baseUrl,
      'X-Cache-Hit': result.fromCache ? 'true' : 'false',
      'X-Response-Time': `${duration}ms`,
      'X-Batch-ID': req.batchId || 'none',
      'X-API-Name': req.apiName
    });
    
    // Forward status and data
    res.status(result.status || 200).json(result.data);
    
  } catch (error) {
    const duration = Date.now() - startTime;
    
    // Log proxy error
    AppLogger.logProxyError(
      req.apiName,
      req.originalUrl,
      error,
      duration
    );
    
    // Determine appropriate status code
    let status = error.status || 500;
    let message = error.message || 'Proxy error';
    
    // Handle specific error types
    if (error.code === 'ECONNREFUSED') {
      status = 502;
      message = 'External API is unreachable';
    } else if (error.code === 'ETIMEDOUT') {
      status = 504;
      message = 'External API timeout';
    } else if (error.response) {
      // Forward external API error
      status = error.response.status;
      message = error.response.data?.message || error.response.statusText;
    }
    
    res.status(status).json({
      error: 'Proxy Error',
      message,
      api: req.apiName,
      originalUrl: req.originalUrl,
      batchId: req.batchId,
      timestamp: new Date().toISOString(),
      suggestion: 'Please check the external API status or contact administrator'
    });
  }
}

// Health check for proxy services
export async function checkProxyHealth(req, res) {
  try {
    const healthChecks = [];
    
    for (const [apiName, config] of Object.entries(API_ROUTES)) {
      try {
        const proxyService = getProxyService(apiName);
        const startTime = Date.now();
        
        // Try to reach the external API
        const testUrl = `${proxyService.config.baseUrl}/`; // Root endpoint
        const response = await axios.get(testUrl, { timeout: 3000 });
        
        const duration = Date.now() - startTime;
        
        healthChecks.push({
          api: apiName,
          name: proxyService.config.name,
          baseUrl: proxyService.config.baseUrl,
          status: 'healthy',
          responseTime: `${duration}ms`,
          statusCode: response.status,
          requiresAuth: proxyService.config.requiresAuth
        });
      } catch (error) {
        healthChecks.push({
          api: apiName,
          name: proxyService.config.name,
          baseUrl: proxyService.config.baseUrl,
          status: 'unhealthy',
          error: error.message,
          requiresAuth: proxyService.config.requiresAuth
        });
      }
    }
    
    const healthyCount = healthChecks.filter(h => h.status === 'healthy').length;
    const totalCount = healthChecks.length;
    
    return res.json({
      success: true,
      timestamp: new Date().toISOString(),
      summary: {
        total: totalCount,
        healthy: healthyCount,
        unhealthy: totalCount - healthyCount,
        healthPercentage: ((healthyCount / totalCount) * 100).toFixed(2)
      },
      services: healthChecks,
      cache: AppCache.getStats()
    });
    
  } catch (error) {
    console.error('Proxy health check error:', error);
    return res.status(500).json({
      error: 'Health check failed',
      message: error.message
    });
  }
}

// Batch permission pre-check middleware
export function preCheckBatchPermission(req, res, next) {
  // Skip batch check for non-batch endpoints
  const nonBatchEndpoints = ['/info', '/health', '/stats', '/docs'];
  if (nonBatchEndpoints.some(endpoint => req.path.endsWith(endpoint))) {
    return next();
  }
  
  // If no batch ID in request, continue
  if (!req.batchId) {
    return next();
  }
  
  // Check cache for batch permission
  const cacheKey = `batch:permission:${req.user?.id}:${req.batchId}`;
  const cachedPermission = AppCache.get(cacheKey);
  
  if (cachedPermission !== null) {
    if (cachedPermission === true) {
      return next();
    } else {
      return res.status(403).json({
        error: 'Batch permission denied (cached)',
        batchId: req.batchId,
        userId: req.user?.username
      });
    }
  }
  
  // Permission not in cache, continue to dynamic check
  next();
}

// Rate limiting for specific APIs
export function createApiRateLimiter(apiName, windowMs = 60000, max = 60) {
  const rateLimit = require('express-rate-limit');
  
  return rateLimit({
    windowMs,
    max,
    keyGenerator: (req) => {
      return `${req.ip}:${apiName}`;
    },
    skip: (req) => {
      // Skip rate limiting for owners/admins
      return req.user?.role === 'owner' || req.user?.role === 'admin';
    },
    message: {
      error: 'Rate limit exceeded',
      message: `Too many requests to ${apiName}. Please try again later.`,
      api: apiName,
      window: `${windowMs / 1000} seconds`,
      limit: max
    }
  });
}

// Export all middleware
export default {
  identifyApi,
  extractBatchId,
  proxyHandler,
  checkProxyHealth,
  preCheckBatchPermission,
  createApiRateLimiter
};