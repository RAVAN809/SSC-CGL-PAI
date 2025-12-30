import NodeCache from 'node-cache';

// Global cache instance for the entire application
const cache = new NodeCache({
  stdTTL: parseInt(process.env.CACHE_DEFAULT_TTL) || 60, // 60 seconds default
  checkperiod: 120,
  useClones: false,
  deleteOnExpire: true
});

// Cache statistics
let stats = {
  hits: 0,
  misses: 0,
  sets: 0,
  deletes: 0,
  flushes: 0
};

export class AppCache {
  // Get value from cache
  static get(key) {
    const value = cache.get(key);
    if (value !== undefined) {
      stats.hits++;
      return value;
    }
    stats.misses++;
    return null;
  }

  // Set value in cache with optional TTL
  static set(key, value, ttl = null) {
    const success = ttl ? 
      cache.set(key, value, ttl) : 
      cache.set(key, value);
    
    if (success) {
      stats.sets++;
    }
    
    return success;
  }

  // Delete key from cache
  static delete(key) {
    const deleted = cache.del(key);
    if (deleted) {
      stats.deletes += deleted;
    }
    return deleted;
  }

  // Clear all cache
  static flush() {
    cache.flushAll();
    stats.flushes++;
    return true;
  }

  // Get cache statistics
  static getStats() {
    const cacheStats = cache.getStats();
    return {
      ...stats,
      totalKeys: cacheStats.keys,
      hits: stats.hits,
      misses: stats.misses,
      hitRate: stats.hits / (stats.hits + stats.misses) || 0
    };
  }

  // Batch-specific cache methods
  static getBatchData(batchId, endpoint, userId = null) {
    const key = userId ? 
      `batch:${batchId}:${endpoint}:user:${userId}` : 
      `batch:${batchId}:${endpoint}`;
    
    return this.get(key);
  }

  static setBatchData(batchId, endpoint, data, userId = null, ttl = 300) {
    const key = userId ? 
      `batch:${batchId}:${endpoint}:user:${userId}` : 
      `batch:${batchId}:${endpoint}`;
    
    return this.set(key, data, ttl);
  }

  // User-specific cache methods
  static getUserData(userId, dataType) {
    return this.get(`user:${userId}:${dataType}`);
  }

  static setUserData(userId, dataType, data, ttl = 600) {
    return this.set(`user:${userId}:${dataType}`, data, ttl);
  }

  // API-specific cache methods
  static getApiResponse(apiName, path, query = {}) {
    const queryString = JSON.stringify(query);
    const key = `api:${apiName}:${path}:${queryString}`;
    return this.get(key);
  }

  static setApiResponse(apiName, path, data, query = {}, ttl = 60) {
    const queryString = JSON.stringify(query);
    const key = `api:${apiName}:${path}:${queryString}`;
    return this.set(key, data, ttl);
  }

  // Clear cache for specific batch
  static clearBatchCache(batchId) {
    const keys = cache.keys();
    const batchKeys = keys.filter(key => key.includes(`batch:${batchId}`));
    batchKeys.forEach(key => this.delete(key));
    return batchKeys.length;
  }

  // Clear cache for specific user
  static clearUserCache(userId) {
    const keys = cache.keys();
    const userKeys = keys.filter(key => key.includes(`user:${userId}`));
    userKeys.forEach(key => this.delete(key));
    return userKeys.length;
  }

  // Check if cache is enabled
  static isEnabled() {
    return process.env.CACHE_ENABLED !== 'false';
  }
}

export default AppCache;