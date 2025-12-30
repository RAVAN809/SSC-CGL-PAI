import axios from 'axios';
import { API_CONFIGS, BATCH_ID_EXTRACTORS } from '../config/apis.js';
import cacheService from './cacheService.js';

// Auto endpoint discovery cache
const endpointCache = new Map();

export class ProxyService {
  constructor(apiName) {
    this.apiName = apiName;
    this.config = API_CONFIGS[apiName];
    this.batchIdExtractor = BATCH_ID_EXTRACTORS[apiName];
  }

  // Discover available endpoints from external API
  async discoverEndpoints() {
    if (endpointCache.has(this.apiName)) {
      return endpointCache.get(this.apiName);
    }

    try {
      // Try common endpoints
      const testEndpoints = [
        { path: '/', method: 'GET' },
        { path: '/batches', method: 'GET' },
        { path: '/batch', method: 'GET' },
        { path: '/courses', method: 'GET' },
        { path: '/api', method: 'GET' }
      ];

      const discovered = [];

      for (const endpoint of testEndpoints) {
        try {
          const url = `${this.config.baseUrl}${endpoint.path}`;
          const response = await axios({
            method: endpoint.method,
            url,
            timeout: 3000
          });

          if (response.status === 200) {
            discovered.push({
              path: endpoint.path,
              method: endpoint.method,
              status: response.status
            });
          }
        } catch (error) {
          // Continue testing other endpoints
          continue;
        }
      }

      endpointCache.set(this.apiName, discovered);
      return discovered;
    } catch (error) {
      console.error(`Endpoint discovery failed for ${this.apiName}:`, error.message);
      return [];
    }
  }

  // Build target URL with automatic endpoint matching
  buildTargetUrl(req) {
    const originalPath = req.originalUrl.replace(`/${this.apiName}`, '');
    const queryString = req.url.includes('?') ? req.url.split('?')[1] : '';
    
    // Try exact mapping first
    if (this.config.pathMapping && this.config.pathMapping[originalPath]) {
      let targetPath = this.config.pathMapping[originalPath];
      
      // Replace path parameters
      Object.keys(req.params).forEach(param => {
        targetPath = targetPath.replace(`:${param}`, req.params[param]);
      });
      
      return `${this.config.baseUrl}${targetPath}${queryString ? '?' + queryString : ''}`;
    }
    
    // Try pattern matching for dynamic paths
    for (const [pattern, mapping] of Object.entries(this.config.pathMapping || {})) {
      if (pattern.includes(':')) {
        const patternRegex = new RegExp('^' + pattern.replace(/:\w+/g, '([^/]+)') + '$');
        const match = originalPath.match(patternRegex);
        
        if (match) {
          let targetPath = mapping;
          for (let i = 1; i < match.length; i++) {
            targetPath = targetPath.replace(`:${Object.keys(req.params)[i-1] || 'param'+i}`, match[i]);
          }
          return `${this.config.baseUrl}${targetPath}${queryString ? '?' + queryString : ''}`;
        }
      }
    }
    
    // Default: append path to base URL
    return `${this.config.baseUrl}${originalPath}${queryString ? '?' + queryString : ''}`;
  }

  // Extract batch ID from request
  extractBatchId(req) {
    if (this.batchIdExtractor) {
      const batchId = this.batchIdExtractor(req);
      return batchId;
    }
    
    // Default extraction logic
    const path = req.path;
    
    // Try to extract from path parameters
    if (req.params.batch_id) return req.params.batch_id;
    if (req.params.id) return req.params.id;
    if (req.params.batchId) return req.params.batchId;
    
    // Try to extract from query parameters
    if (req.query.batchid) return req.query.batchid;
    if (req.query.batch_id) return req.query.batch_id;
    if (req.query.courseid) return req.query.courseid;
    if (req.query.course_id) return req.query.course_id;
    
    // Try to extract from path pattern
    const batchIdPatterns = [
      /\/batch\/([^\/?]+)/,
      /\/batches\/([^\/?]+)/,
      /\/course\/([^\/?]+)/,
      /\/courses\/([^\/?]+)/,
      /\/today\/([^\/?]+)/,
      /\/updates\/([^\/?]+)/
    ];
    
    for (const pattern of batchIdPatterns) {
      const match = path.match(pattern);
      if (match) return match[1];
    }
    
    return null;
  }

  // Make proxy request
  async proxyRequest(req) {
    const targetUrl = this.buildTargetUrl(req);
    const batchId = this.extractBatchId(req);
    
    // Store batch ID in request for permission middleware
    req.batchId = batchId;
    
    // Check cache for GET requests
    if (req.method === 'GET') {
      const cacheKey = `${this.apiName}:${req.method}:${targetUrl}:${JSON.stringify(req.query)}`;
      const cached = cacheService.get(cacheKey);
      if (cached) {
        console.log(`Cache hit for ${cacheKey}`);
        return { data: cached, fromCache: true };
      }
    }
    
    // Prepare headers
    const headers = {
      'User-Agent': 'Ravan-System-Proxy/4.0.0',
      'Accept': 'application/json',
      'X-Forwarded-For': req.ip,
      'X-Proxy-Source': 'ravan-system.vercel.app',
      'X-Original-URL': req.originalUrl
    };
    
    // Forward relevant headers
    const forwardHeaders = [
      'authorization',
      'content-type',
      'accept-language',
      'referer',
      'x-api-key',
      'x-device-token'
    ];
    
    forwardHeaders.forEach(header => {
      if (req.headers[header]) {
        headers[header] = req.headers[header];
      }
    });
    
    // Make the request
    const startTime = Date.now();
    try {
      const response = await axios({
        method: req.method,
        url: targetUrl,
        headers,
        params: req.query,
        data: req.body,
        timeout: parseInt(process.env.PROXY_TIMEOUT || '10000'),
        validateStatus: () => true // Accept all status codes
      });
      
      const duration = Date.now() - startTime;
      
      console.log(`Proxy: ${req.method} ${targetUrl} → ${response.status} (${duration}ms)`);
      
      // Cache successful GET responses
      if (req.method === 'GET' && response.status === 200) {
        const cacheKey = `${this.apiName}:${req.method}:${targetUrl}:${JSON.stringify(req.query)}`;
        const cacheTtl = this.getCacheTtl(req.path);
        cacheService.set(cacheKey, response.data, cacheTtl);
      }
      
      return {
        data: response.data,
        status: response.status,
        headers: response.headers,
        duration
      };
      
    } catch (error) {
      const duration = Date.now() - startTime;
      console.error(`Proxy error for ${targetUrl}:`, error.message);
      
      throw {
        status: error.response?.status || 502,
        message: error.response?.data?.message || error.message,
        data: error.response?.data,
        duration
      };
    }
  }

  // Get cache TTL based on endpoint
  getCacheTtl(path) {
    const ttlConfig = {
      '/batches': 300, // 5 minutes for batch lists
      '/batch': 60,    // 1 minute for batch details
      '/today': 60,    // 1 minute for today's content
      default: 30      // 30 seconds for others
    };
    
    for (const [key, ttl] of Object.entries(ttlConfig)) {
      if (path.includes(key)) {
        return ttl;
      }
    }
    
    return ttlConfig.default;
  }

  // Get API information
  getApiInfo() {
    return {
      name: this.config.name,
      baseUrl: this.config.baseUrl,
      requiresAuth: this.config.requiresAuth,
      endpoints: this.config.endpoints || {},
      discoveredEndpoints: endpointCache.get(this.apiName) || []
    };
  }
}

// Factory function to get proxy service
export function getProxyService(apiName) {
  if (!API_CONFIGS[apiName]) {
    throw new Error(`Unknown API: ${apiName}`);
  }
  return new ProxyService(apiName);
}