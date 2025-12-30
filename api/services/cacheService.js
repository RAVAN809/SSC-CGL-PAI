import NodeCache from 'node-cache';

class CacheService {
  constructor() {
    this.cache = new NodeCache({ 
      stdTTL: 60, // Default TTL: 60 seconds
      checkperiod: 120,
      useClones: false
    });
    
    this.stats = {
      hits: 0,
      misses: 0,
      sets: 0,
      deletes: 0
    };
  }

  get(key) {
    const value = this.cache.get(key);
    if (value !== undefined) {
      this.stats.hits++;
      return value;
    }
    this.stats.misses++;
    return null;
  }

  set(key, value, ttl = null) {
    const success = ttl ? 
      this.cache.set(key, value, ttl) : 
      this.cache.set(key, value);
    
    if (success) {
      this.stats.sets++;
    }
    
    return success;
  }

  delete(key) {
    const deleted = this.cache.del(key);
    if (deleted) {
      this.stats.deletes += deleted;
    }
    return deleted;
  }

  flush() {
    this.cache.flushAll();
    this.stats = { hits: 0, misses: 0, sets: 0, deletes: 0 };
  }

  getStats() {
    return {
      ...this.stats,
      keys: this.cache.keys().length,
      size: this.cache.getStats().keys
    };
  }

  // Batch-specific caching
  getBatchData(batchId, endpoint) {
    return this.get(`batch:${batchId}:${endpoint}`);
  }

  setBatchData(batchId, endpoint, data, ttl = 300) {
    return this.set(`batch:${batchId}:${endpoint}`, data, ttl);
  }

  // User-specific caching
  getUserBatchData(userId, batchId) {
    return this.get(`user:${userId}:batch:${batchId}`);
  }

  setUserBatchData(userId, batchId, data, ttl = 600) {
    return this.set(`user:${userId}:batch:${batchId}`, data, ttl);
  }
}

export default new CacheService();