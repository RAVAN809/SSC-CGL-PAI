import User from '../models/User.js';
import AppCache from '../cache.js';
import Validator from '../utils/validator.js';

export class PermissionService {
  // Check if user has access to a specific batch
  static async checkBatchPermission(userId, batchId) {
    if (!userId || !batchId) {
      return false;
    }
    
    // Check cache first
    const cacheKey = `permission:${userId}:${batchId}`;
    const cachedPermission = AppCache.get(cacheKey);
    
    if (cachedPermission !== undefined) {
      return cachedPermission;
    }
    
    try {
      const user = await User.findById(userId);
      
      if (!user) {
        AppCache.set(cacheKey, false, 60); // Cache negative result for 1 minute
        return false;
      }
      
      // Owners and admins have all access
      if (user.role === 'owner' || user.role === 'admin') {
        AppCache.set(cacheKey, true, 300); // Cache for 5 minutes
        return true;
      }
      
      // Check if user has access to this batch
      const hasAccess = 
        user.allowedBatches.includes('all') || 
        user.allowedBatches.includes(batchId);
      
      // Cache the result
      AppCache.set(cacheKey, hasAccess, 300); // Cache for 5 minutes
      
      return hasAccess;
      
    } catch (error) {
      console.error('Permission check error:', error);
      return false;
    }
  }
  
  // Check if user has access to multiple batches
  static async checkBatchPermissions(userId, batchIds) {
    if (!userId || !Array.isArray(batchIds)) {
      return {};
    }
    
    const results = {};
    const uncachedBatchIds = [];
    
    // Check cache for each batch
    for (const batchId of batchIds) {
      const cacheKey = `permission:${userId}:${batchId}`;
      const cachedPermission = AppCache.get(cacheKey);
      
      if (cachedPermission !== undefined) {
        results[batchId] = cachedPermission;
      } else {
        uncachedBatchIds.push(batchId);
      }
    }
    
    // If all permissions were cached, return results
    if (uncachedBatchIds.length === 0) {
      return results;
    }
    
    // Fetch uncached permissions from database
    try {
      const user = await User.findById(userId);
      
      if (!user) {
        // Cache negative results for all uncached batches
        uncachedBatchIds.forEach(batchId => {
          const cacheKey = `permission:${userId}:${batchId}`;
          AppCache.set(cacheKey, false, 60);
          results[batchId] = false;
        });
        return results;
      }
      
      const isAdmin = user.role === 'owner' || user.role === 'admin';
      const userAllowedBatches = new Set(user.allowedBatches || []);
      const hasAllAccess = userAllowedBatches.has('all');
      
      // Check each uncached batch
      for (const batchId of uncachedBatchIds) {
        const hasAccess = isAdmin || hasAllAccess || userAllowedBatches.has(batchId);
        
        // Cache the result
        const cacheKey = `permission:${userId}:${batchId}`;
        AppCache.set(cacheKey, hasAccess, 300);
        
        results[batchId] = hasAccess;
      }
      
      return results;
      
    } catch (error) {
      console.error('Batch permissions check error:', error);
      
      // Cache negative results on error
      uncachedBatchIds.forEach(batchId => {
        const cacheKey = `permission:${userId}:${batchId}`;
        AppCache.set(cacheKey, false, 60);
        results[batchId] = false;
      });
      
      return results;
    }
  }
  
  // Get user's allowed batches
  static async getUserBatches(userId) {
    if (!userId) {
      return [];
    }
    
    // Check cache
    const cacheKey = `user:${userId}:allowedBatches`;
    const cachedBatches = AppCache.get(cacheKey);
    
    if (cachedBatches !== undefined) {
      return cachedBatches;
    }
    
    try {
      const user = await User.findById(userId);
      
      if (!user) {
        AppCache.set(cacheKey, [], 60);
        return [];
      }
      
      // Owners and admins implicitly have access to all batches
      if (user.role === 'owner' || user.role === 'admin') {
        AppCache.set(cacheKey, ['all'], 300);
        return ['all'];
      }
      
      const allowedBatches = user.allowedBatches || [];
      AppCache.set(cacheKey, allowedBatches, 300);
      
      return allowedBatches;
      
    } catch (error) {
      console.error('Get user batches error:', error);
      return [];
    }
  }
  
  // Validate and sanitize batch IDs for user assignment
  static async validateBatchesForUser(batchIds, assigningUserId) {
    if (!Array.isArray(batchIds)) {
      return { isValid: false, error: 'Batch IDs must be an array' };
    }
    
    // Get the assigning user's permissions
    const assigningUser = await User.findById(assigningUserId);
    if (!assigningUser) {
      return { isValid: false, error: 'Assigning user not found' };
    }
    
    // Owners can assign any batch
    if (assigningUser.role === 'owner') {
      const validatedBatches = [];
      const errors = [];
      
      for (const batchId of batchIds) {
        const validation = Validator.validateBatchId(batchId);
        if (validation.isValid) {
          validatedBatches.push(validation.value);
        } else {
          errors.push(`Invalid batch ID: ${batchId}`);
        }
      }
      
      return {
        isValid: errors.length === 0,
        validatedBatches,
        errors: errors.length > 0 ? errors : undefined
      };
    }
    
    // Admins can only assign batches they have access to
    if (assigningUser.role === 'admin') {
      const adminBatches = new Set(assigningUser.allowedBatches || []);
      const canAssignAll = adminBatches.has('all');
      
      const validatedBatches = [];
      const errors = [];
      
      for (const batchId of batchIds) {
        // Validate batch ID format
        const validation = Validator.validateBatchId(batchId);
        if (!validation.isValid) {
          errors.push(`Invalid batch ID format: ${batchId}`);
          continue;
        }
        
        // Check if admin can assign this batch
        if (canAssignAll || adminBatches.has(batchId)) {
          validatedBatches.push(validation.value);
        } else {
          errors.push(`Admin cannot assign batch: ${batchId}`);
        }
      }
      
      return {
        isValid: errors.length === 0,
        validatedBatches,
        errors: errors.length > 0 ? errors : undefined
      };
    }
    
    // Regular users cannot assign batches
    return {
      isValid: false,
      error: 'Regular users cannot assign batches'
    };
  }
  
  // Check if user can manage another user
  static async canManageUser(managerId, targetUserId) {
    if (!managerId || !targetUserId) {
      return false;
    }
    
    // Same user can always manage themselves (for profile updates)
    if (managerId.toString() === targetUserId.toString()) {
      return true;
    }
    
    try {
      const [manager, target] = await Promise.all([
        User.findById(managerId),
        User.findById(targetUserId)
      ]);
      
      if (!manager || !target) {
        return false;
      }
      
      // Owners can manage anyone
      if (manager.role === 'owner') {
        return true;
      }
      
      // Admins can only manage regular users (not other admins or owners)
      if (manager.role === 'admin') {
        return target.role === 'user';
      }
      
      // Regular users cannot manage anyone else
      return false;
      
    } catch (error) {
      console.error('Can manage user check error:', error);
      return false;
    }
  }
  
  // Clear permission cache for a user
  static clearUserPermissionCache(userId) {
    if (!userId) return;
    
    // Clear all permission-related cache for this user
    const keys = AppCache.cache.keys();
    const userKeys = keys.filter(key => 
      key.includes(`permission:${userId}:`) || 
      key.includes(`user:${userId}:`)
    );
    
    userKeys.forEach(key => AppCache.delete(key));
    
    return userKeys.length;
  }
  
  // Clear permission cache for a batch
  static clearBatchPermissionCache(batchId) {
    if (!batchId) return;
    
    const keys = AppCache.cache.keys();
    const batchKeys = keys.filter(key => key.includes(`:${batchId}`));
    
    batchKeys.forEach(key => AppCache.delete(key));
    
    return batchKeys.length;
  }
  
  // Get user's permission summary
  static async getUserPermissionSummary(userId) {
    if (!userId) {
      return null;
    }
    
    try {
      const user = await User.findById(userId);
      
      if (!user) {
        return null;
      }
      
      const now = new Date();
      const isExpired = user.expiresAt && user.expiresAt < now;
      
      return {
        userId: user._id,
        username: user.username,
        role: user.role,
        allowedBatches: user.allowedBatches || [],
        hasAllAccess: user.allowedBatches?.includes('all') || false,
        isAdmin: user.role === 'owner' || user.role === 'admin',
        isOwner: user.role === 'owner',
        isActive: !isExpired,
        expiresAt: user.expiresAt,
        deviceCount: user.deviceTokens?.length || 0,
        canManageUsers: user.role === 'owner' || user.role === 'admin',
        canAssignBatches: user.role === 'owner' || user.role === 'admin'
      };
      
    } catch (error) {
      console.error('Get user permission summary error:', error);
      return null;
    }
  }
  
  // Check API key permissions
  static async checkApiKeyPermission(apiKey, batchId) {
    if (!apiKey || !batchId) {
      return false;
    }
    
    // Check if API key is valid
    const validApiKeys = process.env.VALID_API_KEYS?.split(',') || [];
    if (!validApiKeys.includes(apiKey)) {
      return false;
    }
    
    // Check batch access for API key
    const apiKeyBatches = process.env.API_KEY_BATCHES?.split(',') || [];
    
    return apiKeyBatches.includes('all') || apiKeyBatches.includes(batchId);
  }
  
  // Validate user can access endpoint based on batch in URL
  static async validateEndpointAccess(user, req) {
    if (!user) {
      return { allowed: false, reason: 'User not authenticated' };
    }
    
    // Extract batch ID from request
    const { extractBatchIdFromUrl } = await import('../utils/helpers.js');
    const batchId = extractBatchIdFromUrl(req.originalUrl);
    
    if (!batchId) {
      // No batch ID in URL, allow access
      return { allowed: true };
    }
    
    // Check batch permission
    const hasPermission = await this.checkBatchPermission(user.id, batchId);
    
    if (!hasPermission) {
      return {
        allowed: false,
        reason: 'No permission for this batch',
        batchId,
        userBatches: user.allowedBatches || []
      };
    }
    
    return { allowed: true, batchId };
  }
}

export default PermissionService;