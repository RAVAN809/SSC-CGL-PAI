import crypto from 'crypto';

export class Helpers {
  // Generate random string
  static generateRandomString(length = 32) {
    return crypto
      .randomBytes(Math.ceil(length / 2))
      .toString('hex')
      .slice(0, length);
  }
  
  // Generate API key
  static generateApiKey() {
    return `sk_${this.generateRandomString(48)}`;
  }
  
  // Generate device token
  static generateDeviceToken() {
    return `dev_${this.generateRandomString(32)}`;
  }
  
  // Hash string (for API keys, tokens, etc.)
  static hashString(str) {
    return crypto
      .createHash('sha256')
      .update(str)
      .digest('hex');
  }
  
  // Extract batch ID from various URL patterns
  static extractBatchIdFromUrl(url) {
    const patterns = [
      /\/batch\/([^\/?]+)/,
      /\/batches\/([^\/?]+)/,
      /\/course\/([^\/?]+)/,
      /\/courses\/([^\/?]+)/,
      /\/today\/([^\/?]+)/,
      /\/updates\/([^\/?]+)/,
      /\/classroom\/([^\/?]+)/,
      /\/timetable\/([^\/?]+)/,
      /batch[Ii]d=([^&]+)/,
      /course[Ii]d=([^&]+)/
    ];
    
    for (const pattern of patterns) {
      const match = url.match(pattern);
      if (match) {
        return match[1];
      }
    }
    
    return null;
  }
  
  // Build URL with query parameters
  static buildUrl(baseUrl, params = {}) {
    const url = new URL(baseUrl);
    
    Object.entries(params).forEach(([key, value]) => {
      if (value !== undefined && value !== null) {
        url.searchParams.append(key, value.toString());
      }
    });
    
    return url.toString();
  }
  
  // Parse query string to object
  static parseQueryString(queryString) {
    const params = {};
    
    if (!queryString) return params;
    
    queryString.split('&').forEach(pair => {
      const [key, value] = pair.split('=');
      if (key) {
        params[decodeURIComponent(key)] = decodeURIComponent(value || '');
      }
    });
    
    return params;
  }
  
  // Deep merge objects
  static deepMerge(target, ...sources) {
    if (!sources.length) return target;
    const source = sources.shift();
    
    if (this.isObject(target) && this.isObject(source)) {
      for (const key in source) {
        if (this.isObject(source[key])) {
          if (!target[key]) Object.assign(target, { [key]: {} });
          this.deepMerge(target[key], source[key]);
        } else {
          Object.assign(target, { [key]: source[key] });
        }
      }
    }
    
    return this.deepMerge(target, ...sources);
  }
  
  // Check if value is an object
  static isObject(item) {
    return item && typeof item === 'object' && !Array.isArray(item);
  }
  
  // Delay function
  static delay(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
  
  // Retry function with exponential backoff
  static async retry(fn, retries = 3, delayMs = 1000) {
    let lastError;
    
    for (let i = 0; i < retries; i++) {
      try {
        return await fn();
      } catch (error) {
        lastError = error;
        if (i < retries - 1) {
          await this.delay(delayMs * Math.pow(2, i)); // Exponential backoff
        }
      }
    }
    
    throw lastError;
  }
  
  // Calculate expiry date
  static calculateExpiryDate(minutesFromNow) {
    if (!minutesFromNow || minutesFromNow <= 0) {
      return null;
    }
    
    const now = new Date();
    return new Date(now.getTime() + minutesFromNow * 60000);
  }
  
  // Format date for display
  static formatDate(date, format = 'iso') {
    if (!date) return 'Never';
    
    const d = new Date(date);
    
    switch (format) {
      case 'iso':
        return d.toISOString();
      case 'local':
        return d.toLocaleString();
      case 'relative':
        return this.getRelativeTime(d);
      case 'date':
        return d.toLocaleDateString();
      case 'time':
        return d.toLocaleTimeString();
      default:
        return d.toISOString();
    }
  }
  
  // Get relative time (e.g., "2 hours ago")
  static getRelativeTime(date) {
    const now = new Date();
    const diffMs = now - date;
    const diffSec = Math.floor(diffMs / 1000);
    const diffMin = Math.floor(diffSec / 60);
    const diffHour = Math.floor(diffMin / 60);
    const diffDay = Math.floor(diffHour / 24);
    
    if (diffSec < 60) return 'just now';
    if (diffMin < 60) return `${diffMin} minute${diffMin > 1 ? 's' : ''} ago`;
    if (diffHour < 24) return `${diffHour} hour${diffHour > 1 ? 's' : ''} ago`;
    if (diffDay < 30) return `${diffDay} day${diffDay > 1 ? 's' : ''} ago`;
    
    const diffMonth = Math.floor(diffDay / 30);
    if (diffMonth < 12) return `${diffMonth} month${diffMonth > 1 ? 's' : ''} ago`;
    
    const diffYear = Math.floor(diffMonth / 12);
    return `${diffYear} year${diffYear > 1 ? 's' : ''} ago`;
  }
  
  // Truncate string
  static truncate(str, length = 100) {
    if (!str || str.length <= length) return str;
    return str.substring(0, length) + '...';
  }
  
  // Mask sensitive data
  static maskSensitive(data) {
    if (typeof data === 'string') {
      // Mask tokens, keys, passwords
      if (data.length > 20 && (data.startsWith('Bearer ') || data.includes('sk_') || data.includes('dev_'))) {
        return data.substring(0, 10) + '...' + data.substring(data.length - 4);
      }
      return data;
    }
    
    if (Array.isArray(data)) {
      return data.map(item => this.maskSensitive(item));
    }
    
    if (typeof data === 'object' && data !== null) {
      const masked = {};
      for (const key in data) {
        if (['password', 'token', 'key', 'secret', 'auth'].some(s => key.toLowerCase().includes(s))) {
          masked[key] = '***MASKED***';
        } else {
          masked[key] = this.maskSensitive(data[key]);
        }
      }
      return masked;
    }
    
    return data;
  }
  
  // Get user agent info
  static parseUserAgent(uaString) {
    if (!uaString) return { browser: 'Unknown', os: 'Unknown', device: 'Unknown' };
    
    const browserMatch = uaString.match(/(chrome|firefox|safari|edge|opera|msie|trident)/i);
    const osMatch = uaString.match(/(windows|mac os|linux|android|ios)/i);
    const deviceMatch = uaString.match(/(mobile|tablet|ipad|iphone|android)/i);
    
    return {
      browser: browserMatch ? browserMatch[0] : 'Unknown',
      os: osMatch ? osMatch[0] : 'Unknown',
      device: deviceMatch ? deviceMatch[0] : 'Desktop',
      raw: uaString.substring(0, 200)
    };
  }
  
  // Validate URL
  static isValidUrl(string) {
    try {
      new URL(string);
      return true;
    } catch (_) {
      return false;
    }
  }
}

export default Helpers;