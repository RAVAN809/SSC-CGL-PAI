import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import User from '../models/User.js';
import { requireAuth } from '../middleware/auth.js';
import { authLimiter } from '../middleware/rateLimit.js';
import Validator from '../utils/validator.js';
import AppCache from '../cache.js';
import { Helpers } from '../utils/helpers.js';

const router = express.Router();

// Apply rate limiting to auth endpoints
router.use(authLimiter);

// POST /auth/login - User login
router.post('/login', async (req, res) => {
  try {
    const { username, password, deviceToken, deviceInfo } = req.body || {};
    
    // Validate input
    const validation = Validator.validateLoginData({
      username,
      password,
      deviceToken,
      deviceInfo
    });
    
    if (!validation.isValid) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: validation.errors 
      });
    }
    
    const { data } = validation;
    
    // Find user
    const user = await User.findOne({ username: data.username });
    if (!user) {
      return res.status(401).json({ 
        error: 'Invalid credentials',
        message: 'Username or password is incorrect'
      });
    }

    // Check if account is expired
    if (user.expiresAt && user.expiresAt < new Date()) {
      return res.status(401).json({ 
        error: 'Account expired',
        message: 'Your account has expired. Please contact an administrator.',
        expiresAt: user.expiresAt
      });
    }

    // Verify password
    const passwordValid = await bcrypt.compare(data.password, user.passwordHash);
    if (!passwordValid) {
      return res.status(401).json({ 
        error: 'Invalid credentials',
        message: 'Username or password is incorrect'
      });
    }

    // Check device limit
    if (data.deviceToken && user.deviceTokens?.length >= 10) {
      // Remove oldest device if limit reached
      user.deviceTokens.sort((a, b) => new Date(a.lastActive) - new Date(b.lastActive));
      user.deviceTokens.shift();
    }
    
    // Add or update device token
    if (data.deviceToken) {
      const existingDevice = user.deviceTokens?.find(d => d.token === data.deviceToken);
      if (existingDevice) {
        // Update existing device
        existingDevice.lastActive = new Date();
        existingDevice.loggedInAt = new Date();
        if (data.deviceInfo) {
          existingDevice.deviceInfo = data.deviceInfo.substring(0, 200);
        }
      } else {
        // Add new device
        user.deviceTokens = user.deviceTokens || [];
        user.deviceTokens.push({
          token: data.deviceToken,
          deviceInfo: (data.deviceInfo || 'Unknown Device').substring(0, 200),
          loggedInAt: new Date(),
          lastActive: new Date()
        });
      }
      await user.save();
    }

    // Create JWT token
    const tokenPayload = {
      sub: user._id,
      username: user.username,
      role: user.role,
      name: user.name,
      allowedBatches: user.allowedBatches || []
    };
    
    const token = jwt.sign(
      tokenPayload,
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );

    // Clear user cache
    AppCache.clearUserCache(user._id.toString());

    return res.json({
      success: true,
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        username: user.username,
        name: user.name,
        role: user.role,
        allowedBatches: user.allowedBatches || [],
        expiresAt: user.expiresAt,
        deviceCount: user.deviceTokens?.length || 0,
        requiresPasswordChange: false // Could be used for password rotation
      },
      session: {
        expiresIn: process.env.JWT_EXPIRES_IN || '7d',
        issuedAt: new Date().toISOString()
      }
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ 
      error: 'Login failed', 
      message: 'An error occurred during login. Please try again.' 
    });
  }
});

// POST /auth/register - User registration (admin/owner only)
router.post('/register', requireAuth, async (req, res) => {
  try {
    // Only admins and owners can register users
    if (req.user.role !== 'admin' && req.user.role !== 'owner') {
      return res.status(403).json({ error: 'Only admins can register users' });
    }
    
    const { username, name, password, allowedBatches, expiresInMinutes, role = 'user' } = req.body || {};
    
    // Validate input
    const validation = Validator.validateUserData({
      username,
      name,
      password,
      role,
      allowedBatches,
      expiresInMinutes
    });
    
    if (!validation.isValid) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: validation.errors 
      });
    }
    
    // Check permissions for role assignment
    if ((role === 'admin' || role === 'owner') && req.user.role !== 'owner') {
      return res.status(403).json({ error: 'Only owner can create admin/owner users' });
    }
    
    // Check if username exists
    const exists = await User.findOne({ username });
    if (exists) {
      return res.status(409).json({ 
        error: 'Username exists', 
        message: 'Username is already taken. Please choose another.' 
      });
    }
    
    // Hash password
    const passwordHash = await bcrypt.hash(password, 12);
    
    // Calculate expiry
    let expiresAt = null;
    if (expiresInMinutes && expiresInMinutes > 0) {
      expiresAt = new Date(Date.now() + expiresInMinutes * 60000);
    }
    
    // Create user
    const user = await User.create({
      username,
      name,
      role,
      passwordHash,
      allowedBatches: allowedBatches === 'all' ? ['all'] : (Array.isArray(allowedBatches) ? allowedBatches : []),
      expiresAt
    });

    return res.status(201).json({
      success: true,
      message: 'User registered successfully',
      user: {
        id: user._id,
        username: user.username,
        name: user.name,
        role: user.role,
        allowedBatches: user.allowedBatches,
        expiresAt: user.expiresAt
      }
    });
  } catch (err) {
    console.error('Registration error:', err);
    return res.status(500).json({ error: 'Registration failed' });
  }
});

// POST /auth/refresh - Refresh token
router.post('/refresh', async (req, res) => {
  try {
    const { refreshToken } = req.body;
    
    if (!refreshToken) {
      return res.status(400).json({ error: 'Refresh token required' });
    }
    
    // Verify refresh token
    const payload = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET || process.env.JWT_SECRET);
    
    // Find user
    const user = await User.findById(payload.sub);
    if (!user) {
      return res.status(401).json({ error: 'User not found' });
    }
    
    // Check if account expired
    if (user.expiresAt && user.expiresAt < new Date()) {
      return res.status(401).json({ error: 'Account expired' });
    }
    
    // Create new access token
    const newToken = jwt.sign(
      {
        sub: user._id,
        username: user.username,
        role: user.role,
        name: user.name,
        allowedBatches: user.allowedBatches || []
      },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
    );
    
    return res.json({
      success: true,
      message: 'Token refreshed',
      token: newToken,
      expiresIn: process.env.JWT_EXPIRES_IN || '7d'
    });
  } catch (err) {
    if (err.name === 'JsonWebTokenError' || err.name === 'TokenExpiredError') {
      return res.status(401).json({ error: 'Invalid or expired refresh token' });
    }
    console.error('Token refresh error:', err);
    return res.status(500).json({ error: 'Token refresh failed' });
  }
});

// GET /auth/profile - Get current user profile
router.get('/profile', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.sub, { passwordHash: 0 });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    return res.json({
      success: true,
      user: {
        id: user._id,
        username: user.username,
        name: user.name,
        role: user.role,
        allowedBatches: user.allowedBatches || [],
        expiresAt: user.expiresAt,
        deviceCount: user.deviceTokens?.length || 0,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
      }
    });
  } catch (err) {
    console.error('Profile fetch error:', err);
    return res.status(500).json({ error: 'Failed to fetch profile' });
  }
});

// PUT /auth/profile - Update current user profile
router.put('/profile', requireAuth, async (req, res) => {
  try {
    const { name, currentPassword, newPassword } = req.body || {};
    const userId = req.user.sub;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    // Update name if provided
    if (name) {
      if (typeof name === 'string' && name.trim().length >= 2) {
        user.name = name.trim();
      } else {
        return res.status(400).json({ error: 'Name must be at least 2 characters' });
      }
    }
    
    // Update password if provided
    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({ error: 'Current password required to change password' });
      }
      
      // Verify current password
      const passwordValid = await bcrypt.compare(currentPassword, user.passwordHash);
      if (!passwordValid) {
        return res.status(401).json({ error: 'Current password is incorrect' });
      }
      
      // Validate new password
      const passwordValidation = Validator.validatePassword(newPassword);
      if (!passwordValidation.isValid) {
        return res.status(400).json({ 
          error: 'Invalid new password', 
          details: passwordValidation.errors 
        });
      }
      
      user.passwordHash = await bcrypt.hash(newPassword, 12);
    }
    
    await user.save();
    
    // Clear user cache
    AppCache.clearUserCache(user._id.toString());

    return res.json({
      success: true,
      message: 'Profile updated successfully',
      user: {
        id: user._id,
        username: user.username,
        name: user.name,
        role: user.role,
        updatedAt: user.updatedAt
      }
    });
  } catch (err) {
    console.error('Profile update error:', err);
    return res.status(500).json({ error: 'Failed to update profile' });
  }
});

// GET /auth/devices - Get user's logged-in devices
router.get('/devices', requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const now = new Date();
    const devices = (user.deviceTokens || []).map(d => {
      const lastActive = new Date(d.lastActive);
      const loggedInAt = new Date(d.loggedInAt);
      const activeMinutes = Math.round((now - lastActive) / 60000);
      
      return {
        token: d.token, // Full token for current device identification
        maskedToken: d.token.substring(0, 8) + '...' + d.token.substring(d.token.length - 8),
        deviceInfo: d.deviceInfo,
        loggedInAt: loggedInAt,
        lastActive: lastActive,
        activeMinutes,
        isCurrent: req.headers['x-device-token'] === d.token,
        status: activeMinutes < 5 ? 'Online' : 
                activeMinutes < 60 ? 'Recently Active' : 
                'Inactive'
      };
    });

    return res.json({
      success: true,
      username: user.username,
      totalDevices: devices.length,
      activeDevices: devices.filter(d => d.activeMinutes < 60).length,
      devices: devices.sort((a, b) => b.lastActive - a.lastActive)
    });
  } catch (err) {
    console.error('Devices fetch error:', err);
    return res.status(500).json({ error: 'Failed to fetch devices' });
  }
});

// POST /auth/logout-device - Logout specific device
router.post('/logout-device', requireAuth, async (req, res) => {
  try {
    const { deviceToken } = req.body;
    if (!deviceToken) return res.status(400).json({ error: 'Device token required' });

    const user = await User.findById(req.user.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const initialLength = user.deviceTokens?.length || 0;
    user.deviceTokens = (user.deviceTokens || []).filter(d => d.token !== deviceToken);
    
    if (user.deviceTokens.length === initialLength) {
      return res.status(404).json({ error: 'Device not found' });
    }

    await user.save();
    
    // Clear user cache
    AppCache.clearUserCache(user._id.toString());

    return res.json({ 
      success: true, 
      message: 'Device logged out successfully',
      remainingDevices: user.deviceTokens.length 
    });
  } catch (err) {
    console.error('Logout device error:', err);
    return res.status(500).json({ error: 'Failed to logout device' });
  }
});

// POST /auth/logout-all - Logout all devices except current
router.post('/logout-all', requireAuth, async (req, res) => {
  try {
    const currentDeviceToken = req.headers['x-device-token'];
    
    const user = await User.findById(req.user.sub);
    if (!user) return res.status(404).json({ error: 'User not found' });

    const initialLength = user.deviceTokens?.length || 0;
    
    if (currentDeviceToken) {
      // Keep only current device
      user.deviceTokens = (user.deviceTokens || []).filter(d => d.token === currentDeviceToken);
    } else {
      // Logout all devices
      user.deviceTokens = [];
    }
    
    const loggedOutCount = initialLength - user.deviceTokens.length;
    
    await user.save();
    
    // Clear user cache
    AppCache.clearUserCache(user._id.toString());

    return res.json({ 
      success: true, 
      message: `Logged out ${loggedOutCount} device(s)`,
      remainingDevices: user.deviceTokens.length,
      currentDevicePreserved: !!currentDeviceToken
    });
  } catch (err) {
    console.error('Logout all error:', err);
    return res.status(500).json({ error: 'Failed to logout devices' });
  }
});

// GET /auth/check-batch/:batchId - Check batch permission
router.get('/check-batch/:batchId', requireAuth, async (req, res) => {
  try {
    const { batchId } = req.params;
    
    if (!batchId) {
      return res.status(400).json({ error: 'Batch ID required' });
    }
    
    const user = await User.findById(req.user.sub);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const hasPermission = 
      user.role === 'owner' || 
      user.role === 'admin' || 
      user.allowedBatches.includes('all') || 
      user.allowedBatches.includes(batchId);
    
    return res.json({
      success: true,
      hasPermission,
      batchId,
      userRole: user.role,
      allowedBatches: user.allowedBatches,
      message: hasPermission 
        ? `Access granted to batch: ${batchId}` 
        : `No access to batch: ${batchId}`
    });
  } catch (err) {
    console.error('Batch check error:', err);
    return res.status(500).json({ error: 'Failed to check batch permission' });
  }
});

// POST /auth/generate-api-key - Generate API key (owner/admin only)
router.post('/generate-api-key', requireAuth, async (req, res) => {
  try {
    // Only owners and admins can generate API keys
    if (req.user.role !== 'owner' && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only owners and admins can generate API keys' });
    }
    
    const { name, expiresInDays = 90, allowedBatches = ['all'] } = req.body || {};
    
    if (!name || typeof name !== 'string' || name.trim().length < 3) {
      return res.status(400).json({ error: 'API key name must be at least 3 characters' });
    }
    
    // Generate API key
    const apiKey = Helpers.generateApiKey();
    const hashedKey = Helpers.hashString(apiKey);
    
    // Calculate expiry
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + expiresInDays);
    
    // TODO: Store API key in database
    // For now, return the key (in production, store securely)
    
    return res.json({
      success: true,
      message: 'API key generated successfully',
      apiKey: apiKey, // In production, only show this once!
      hashedKey: hashedKey,
      details: {
        name: name.trim(),
        generatedBy: req.user.username,
        expiresAt,
        allowedBatches: Array.isArray(allowedBatches) ? allowedBatches : [allowedBatches],
        note: 'Store this API key securely. It will not be shown again.'
      }
    });
  } catch (err) {
    console.error('API key generation error:', err);
    return res.status(500).json({ error: 'Failed to generate API key' });
  }
});

export default router;