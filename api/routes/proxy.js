import express from 'express';
import { requireAuthWithExpiry, requireDynamicBatchPermission } from '../middleware/auth.js';
import { getProxyService } from '../services/proxyService.js';
import { API_ROUTES } from '../config/apis.js';

const router = express.Router();

// Middleware to identify API from route
router.use((req, res, next) => {
  const path = req.originalUrl;
  
  // Find which API this request is for
  for (const [route, apiName] of Object.entries(API_ROUTES)) {
    if (path.startsWith(route)) {
      req.apiName = apiName;
      break;
    }
  }
  
  if (!req.apiName) {
    return res.status(404).json({ 
      error: 'API not found',
      availableAPIs: Object.keys(API_ROUTES).map(route => ({
        route,
        name: API_ROUTES[route]
      }))
    });
  }
  
  next();
});

// Get API information
router.get('/info', requireAuthWithExpiry, async (req, res) => {
  try {
    const proxyService = getProxyService(req.apiName);
    const info = proxyService.getApiInfo();
    
    // Try to discover endpoints
    const discovered = await proxyService.discoverEndpoints();
    
    res.json({
      api: req.apiName,
      info,
      discoveredEndpoints: discovered,
      proxyUrl: `https://ravan-system.vercel.app/${req.apiName}`,
      originalUrl: info.baseUrl
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Main proxy handler - matches all routes
router.all('/*', requireAuthWithExpiry, requireDynamicBatchPermission, async (req, res) => {
  try {
    const proxyService = getProxyService(req.apiName);
    
    // Check if authentication is required for this API
    if (proxyService.config.requiresAuth && !req.user) {
      return res.status(401).json({ error: 'Authentication required for this API' });
    }
    
    // Make proxy request
    const result = await proxyService.proxyRequest(req);
    
    // Add proxy headers
    res.set({
      'X-Proxy-Server': 'Ravan System',
      'X-Proxied-From': proxyService.config.baseUrl,
      'X-Cache-Hit': result.fromCache ? 'true' : 'false',
      'X-Response-Time': `${result.duration}ms`
    });
    
    // Forward status and data
    res.status(result.status || 200).json(result.data);
    
  } catch (error) {
    console.error(`Proxy error for ${req.apiName}:`, error);
    
    const status = error.status || 500;
    const message = error.message || 'Proxy error';
    
    res.status(status).json({
      error: message,
      api: req.apiName,
      originalUrl: req.originalUrl,
      timestamp: new Date().toISOString()
    });
  }
});

// Batch-specific endpoints auto-registration
const batchEndpoints = [
  { method: 'GET', path: '/batches' },
  { method: 'GET', path: '/batch/:id/full' },
  { method: 'GET', path: '/batch/:id/today' },
  { method: 'GET', path: '/batch/:batch_id' },
  { method: 'GET', path: '/today/:batch_id' },
  { method: 'GET', path: '/updates/:batch_id' },
  { method: 'GET', path: '/classroom/:batch_id' },
  { method: 'GET', path: '/timetable/:batch_id' },
  { method: 'GET', path: '/lesson/:lesson_id' }
];

// Register batch endpoints explicitly for better logging
batchEndpoints.forEach(endpoint => {
  router[endpoint.method.toLowerCase()](endpoint.path, requireAuthWithExpiry, requireDynamicBatchPermission, async (req, res) => {
    try {
      const proxyService = getProxyService(req.apiName);
      const result = await proxyService.proxyRequest(req);
      
      res.set({
        'X-Proxy-Server': 'Ravan System',
        'X-Batch-ID': req.batchId || 'unknown',
        'X-Cache-Hit': result.fromCache ? 'true' : 'false'
      });
      
      res.status(result.status || 200).json(result.data);
    } catch (error) {
      res.status(error.status || 500).json({
        error: error.message,
        batchId: req.batchId,
        endpoint: endpoint.path
      });
    }
  });
});

export default router;