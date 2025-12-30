import jwt from 'jsonwebtoken';
import User from '../models/User.js';

// Basic token verification
export function requireAuth(req, res, next) {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing token' });

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    req.user = payload;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Full authentication with expiry check
export async function requireAuthWithExpiry(req, res, next) {
  try {
    // Check API key first
    const apiKey = req.headers['x-api-key'];
    if (apiKey && process.env.VALID_API_KEYS?.split(',').includes(apiKey)) {
      req.user = { role: 'api_user', authType: 'api_key' };
      return next();
    }

    // Check JWT token
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing token or API key' });

    const payload = jwt.verify(token, process.env.JWT_SECRET);
    
    // Check user in database
    const user = await User.findById(payload.sub).select('-passwordHash');
    if (!user) return res.status(401).json({ error: 'User not found' });
    
    // Check expiry
    if (user.expiresAt && user.expiresAt < new Date()) {
      return res.status(401).json({ error: 'Account expired' });
    }
    
    req.user = {
      ...payload,
      id: user._id,
      allowedBatches: user.allowedBatches || [],
      deviceTokens: user.deviceTokens || []
    };
    
    // Update device activity
    const deviceToken = req.headers['x-device-token'];
    if (deviceToken && user.deviceTokens?.length > 0) {
      const device = user.deviceTokens.find(d => d.token === deviceToken);
      if (device) {
        device.lastActive = new Date();
        await user.save();
      }
    }
    
    next();
  } catch (err) {
    console.error('Auth error:', err.message);
    return res.status(401).json({ error: 'Authentication failed' });
  }
}

// Role-based authorization
export function requireRole(role) {
  return async (req, res, next) => {
    try {
      if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
      
      // API keys have limited access
      if (req.user.authType === 'api_key' && role !== 'user') {
        return res.status(403).json({ error: 'API key cannot access this resource' });
      }
      
      if (req.user.role !== role) {
        return res.status(403).json({ error: `Forbidden: ${role} role required` });
      }
      
      next();
    } catch (err) {
      return res.status(500).json({ error: 'Server error' });
    }
  };
}

// Owner or Admin access
export function requireOwnerOrAdmin(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
  if (req.user.role === 'owner' || req.user.role === 'admin') return next();
  return res.status(403).json({ error: 'Forbidden: owner/admin only' });
}

// Batch permission check
export async function requireBatchPermission(batchId) {
  return async (req, res, next) => {
    try {
      if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
      
      // Owners and admins have all access
      if (req.user.role === 'owner' || req.user.role === 'admin') {
        return next();
      }
      
      // API key users have limited access (configurable)
      if (req.user.authType === 'api_key') {
        const apiKeyBatches = process.env.API_KEY_BATCHES?.split(',') || [];
        if (apiKeyBatches.includes('all') || apiKeyBatches.includes(batchId)) {
          return next();
        }
        return res.status(403).json({ error: 'API key not authorized for this batch' });
      }
      
      // Regular users - check their allowed batches
      const user = await User.findById(req.user.id);
      const allowedBatches = user?.allowedBatches || [];
      
      if (allowedBatches.includes('all') || allowedBatches.includes(batchId)) {
        return next();
      }
      
      return res.status(403).json({ 
        error: 'No permission for this batch',
        yourBatches: allowedBatches,
        requestedBatch: batchId 
      });
    } catch (err) {
      console.error('Permission check error:', err);
      return res.status(500).json({ error: 'Permission check failed' });
    }
  };
}

// Dynamic batch permission based on request
export function requireDynamicBatchPermission(req, res, next) {
  // This will be populated by proxy middleware
  if (req.batchId) {
    return requireBatchPermission(req.batchId)(req, res, next);
  }
  
  // If no batch ID in request, allow access
  next();
}