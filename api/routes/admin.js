import express from 'express';
import bcrypt from 'bcryptjs';
import User from '../models/User.js';
import { requireAuth, requireOwnerOrAdmin } from '../middleware/auth.js';
import Validator from '../utils/validator.js';
import AppCache from '../cache.js';

const router = express.Router();

// Admin (and Owner) can manage users
router.use(requireAuth, requireOwnerOrAdmin);

// GET /admin/users - List all users
router.get('/users', async (req, res) => {
  try {
    const { 
      role = 'user', 
      page = 1, 
      limit = 50,
      search = '',
      sortBy = 'createdAt',
      sortOrder = 'desc'
    } = req.query;
    
    // Validate parameters
    const validRoles = ['owner', 'admin', 'user', 'all'];
    if (!validRoles.includes(role) && role !== 'all') {
      return res.status(400).json({ 
        error: 'Invalid role', 
        validRoles: ['owner', 'admin', 'user', 'all'] 
      });
    }
    
    // Build query
    const query = {};
    if (role !== 'all') {
      query.role = role;
    }
    
    // Search functionality
    if (search) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { name: { $regex: search, $options: 'i' } }
      ];
    }
    
    // Calculate pagination
    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
    const skip = (pageNum - 1) * limitNum;
    
    // Build sort
    const sort = {};
    sort[sortBy] = sortOrder === 'asc' ? 1 : -1;
    
    // Get users with pagination
    const [users, total] = await Promise.all([
      User.find(query, { passwordHash: 0, deviceTokens: 0 })
        .sort(sort)
        .skip(skip)
        .limit(limitNum),
      User.countDocuments(query)
    ]);
    
    // Format response
    const formattedUsers = users.map(user => ({
      id: user._id,
      username: user.username,
      name: user.name,
      role: user.role,
      allowedBatches: user.allowedBatches,
      expiresAt: user.expiresAt,
      deviceCount: user.deviceTokens?.length || 0,
      lastActive: user.deviceTokens?.length > 0 
        ? new Date(Math.max(...user.deviceTokens.map(d => new Date(d.lastActive).getTime())))
        : null,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    }));
    
    return res.json({
      users: formattedUsers,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        pages: Math.ceil(total / limitNum)
      },
      filters: {
        role,
        search,
        sortBy,
        sortOrder
      }
    });
  } catch (err) {
    console.error('Admin users list error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /admin/users/:username - Get user details
router.get('/users/:username', async (req, res) => {
  try {
    const { username } = req.params;
    
    const user = await User.findOne({ username }, { passwordHash: 0 });
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    // Check permissions (only owner can view admin details, admin can view user details)
    if (user.role === 'admin' && req.user.role !== 'owner') {
      return res.status(403).json({ error: 'Only owner can view admin details' });
    }
    
    if (user.role === 'owner' && req.user.role !== 'owner') {
      return res.status(403).json({ error: 'Only owner can view owner details' });
    }
    
    return res.json({
      id: user._id,
      username: user.username,
      name: user.name,
      role: user.role,
      allowedBatches: user.allowedBatches,
      expiresAt: user.expiresAt,
      deviceTokens: user.deviceTokens?.map(token => ({
        token: token.token.substring(0, 10) + '...', // Mask token
        deviceInfo: token.deviceInfo,
        loggedInAt: token.loggedInAt,
        lastActive: token.lastActive,
        isActive: (new Date() - new Date(token.lastActive)) < 24 * 60 * 60 * 1000 // Active within 24 hours
      })) || [],
      deviceCount: user.deviceTokens?.length || 0,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt
    });
  } catch (err) {
    console.error('Admin user details error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// POST /admin/users - Create new user
router.post('/users', async (req, res) => {
  try {
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
    
    // Check if trying to create owner/admin as non-owner
    if ((role === 'owner' || role === 'admin') && req.user.role !== 'owner') {
      return res.status(403).json({ error: 'Only owner can create admin/owner users' });
    }
    
    // Check if username already exists
    const exists = await User.findOne({ username });
    if (exists) return res.status(409).json({ error: 'Username already exists' });
    
    // Hash password
    const passwordHash = await bcrypt.hash(password, 12);
    
    // Calculate expiry time if provided
    let expiresAt = null;
    if (expiresInMinutes && expiresInMinutes > 0) {
      expiresAt = new Date(Date.now() + expiresInMinutes * 60000);
    }
    
    // Validate and sanitize batches
    let validBatches = [];
    if (allowedBatches) {
      if (allowedBatches === 'all') {
        validBatches = ['all'];
      } else if (Array.isArray(allowedBatches)) {
        validBatches = allowedBatches.map(b => b.toString().trim()).filter(b => b);
      }
    }
    
    // Create user
    const user = await User.create({ 
      username, 
      name, 
      role, 
      passwordHash,
      allowedBatches: validBatches,
      expiresAt
    });

    // Clear user cache
    AppCache.clearUserCache(user._id.toString());

    return res.status(201).json({ 
      success: true,
      message: 'User created successfully',
      user: {
        id: user._id, 
        username: user.username, 
        name: user.name, 
        role: user.role,
        allowedBatches: user.allowedBatches,
        expiresAt: user.expiresAt,
        expiresIn: expiresInMinutes ? `${expiresInMinutes} minutes` : 'Never'
      }
    });
  } catch (err) {
    console.error('Admin create user error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// PUT /admin/users/:username - Update user
router.put('/users/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const { 
      name, 
      allowedBatches, 
      expiresInMinutes,
      password,
      role 
    } = req.body || {};
    
    // Find user
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    // Permission checks
    if (user.role === 'owner' && req.user.role !== 'owner') {
      return res.status(403).json({ error: 'Only owner can modify owner' });
    }
    
    if (user.role === 'admin' && req.user.role !== 'owner') {
      return res.status(403).json({ error: 'Only owner can modify admin' });
    }
    
    if (role && role !== user.role) {
      if (req.user.role !== 'owner') {
        return res.status(403).json({ error: 'Only owner can change user role' });
      }
      user.role = role;
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
    if (password) {
      const passwordValidation = Validator.validatePassword(password);
      if (!passwordValidation.isValid) {
        return res.status(400).json({ 
          error: 'Invalid password', 
          details: passwordValidation.errors 
        });
      }
      user.passwordHash = await bcrypt.hash(password, 12);
    }
    
    // Update batches if provided
    if (allowedBatches !== undefined) {
      if (allowedBatches === 'all') {
        user.allowedBatches = ['all'];
      } else if (Array.isArray(allowedBatches)) {
        // Validate each batch ID
        const validBatches = [];
        for (const batch of allowedBatches) {
          const validation = Validator.validateBatchId(batch);
          if (validation.isValid) {
            validBatches.push(validation.value);
          }
        }
        user.allowedBatches = validBatches;
      } else if (allowedBatches === null) {
        user.allowedBatches = [];
      }
    }
    
    // Update expiry if provided
    if (expiresInMinutes !== undefined) {
      if (expiresInMinutes === null || expiresInMinutes === 0) {
        user.expiresAt = null;
      } else if (expiresInMinutes > 0) {
        user.expiresAt = new Date(Date.now() + expiresInMinutes * 60000);
      }
    }
    
    await user.save();
    
    // Clear user cache
    AppCache.clearUserCache(user._id.toString());

    return res.json({ 
      success: true,
      message: 'User updated successfully',
      user: {
        username: user.username,
        name: user.name,
        role: user.role,
        allowedBatches: user.allowedBatches,
        expiresAt: user.expiresAt,
        deviceCount: user.deviceTokens?.length || 0,
        updatedAt: user.updatedAt
      }
    });
  } catch (err) {
    console.error('Admin update user error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /admin/users/:username - Delete user
router.delete('/users/:username', async (req, res) => {
  try {
    const { username } = req.params;
    
    // Prevent deleting owner
    if (username === process.env.OWNER_ID) {
      return res.status(403).json({ error: 'Owner cannot be deleted' });
    }

    const target = await User.findOne({ username });
    if (!target) return res.status(404).json({ error: 'User not found' });

    // Permission checks
    if (target.role === 'owner') {
      return res.status(403).json({ error: 'Owner cannot be deleted' });
    }

    if (target.role === 'admin' && req.user.role !== 'owner') {
      return res.status(403).json({ error: 'Only owner can delete admins' });
    }

    await User.deleteOne({ _id: target._id });
    
    // Clear user cache
    AppCache.clearUserCache(target._id.toString());

    return res.json({ 
      success: true,
      message: 'User deleted successfully',
      deletedUser: {
        username: target.username,
        name: target.name,
        role: target.role
      }
    });
  } catch (err) {
    console.error('Admin delete user error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /admin/user-devices/:username - Get user devices
router.get('/user-devices/:username', async (req, res) => {
  try {
    const { username } = req.params;
    
    const user = await User.findOne({ username }, { passwordHash: 0 });
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    // Check permissions
    if (user.role === 'admin' && req.user.role !== 'owner') {
      return res.status(403).json({ error: 'Only owner can view admin devices' });
    }
    
    if (user.role === 'owner' && req.user.role !== 'owner') {
      return res.status(403).json({ error: 'Only owner can view owner devices' });
    }
    
    const now = new Date();
    const devices = user.deviceTokens?.map(d => {
      const lastActive = new Date(d.lastActive);
      const loggedInAt = new Date(d.loggedInAt);
      const activeMinutes = Math.round((now - lastActive) / 60000);
      const totalMinutes = Math.round((now - loggedInAt) / 60000);
      
      return {
        token: d.token.substring(0, 8) + '...' + d.token.substring(d.token.length - 8), // Mask token
        deviceInfo: d.deviceInfo,
        loggedInAt: loggedInAt,
        lastActive: lastActive,
        activeMinutes,
        totalMinutes,
        isActive: activeMinutes < 60, // Active within last hour
        status: activeMinutes < 5 ? 'Online' : 
                activeMinutes < 60 ? 'Recently Active' : 
                activeMinutes < 24 * 60 ? 'Away' : 'Inactive'
      };
    }) || [];
    
    return res.json({
      username: user.username,
      name: user.name,
      role: user.role,
      totalDevices: devices.length,
      activeDevices: devices.filter(d => d.isActive).length,
      devices: devices.sort((a, b) => b.lastActive - a.lastActive) // Sort by most recent
    });
  } catch (err) {
    console.error('Admin user devices error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// POST /admin/user-devices/:username/revoke - Revoke all devices
router.post('/user-devices/:username/revoke', async (req, res) => {
  try {
    const { username } = req.params;
    
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    // Check permissions
    if (user.role === 'admin' && req.user.role !== 'owner') {
      return res.status(403).json({ error: 'Only owner can revoke admin devices' });
    }
    
    if (user.role === 'owner' && req.user.role !== 'owner') {
      return res.status(403).json({ error: 'Only owner can revoke owner devices' });
    }
    
    const revokedCount = user.deviceTokens?.length || 0;
    user.deviceTokens = [];
    await user.save();
    
    // Clear user cache
    AppCache.clearUserCache(user._id.toString());

    return res.json({ 
      success: true,
      message: `Revoked ${revokedCount} device(s)`,
      revokedCount,
      username: user.username
    });
  } catch (err) {
    console.error('Admin revoke devices error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /admin/stats - Get admin statistics
router.get('/stats', async (req, res) => {
  try {
    // Only owner can access stats
    if (req.user.role !== 'owner') {
      return res.status(403).json({ error: 'Only owner can access statistics' });
    }
    
    const [
      totalUsers,
      totalOwners,
      totalAdmins,
      totalRegularUsers,
      activeUsers,
      expiredUsers,
      cacheStats
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ role: 'owner' }),
      User.countDocuments({ role: 'admin' }),
      User.countDocuments({ role: 'user' }),
      User.countDocuments({ expiresAt: { $gt: new Date() } }),
      User.countDocuments({ expiresAt: { $lt: new Date() } }),
      AppCache.getStats()
    ]);
    
    // Get recent users
    const recentUsers = await User.find({}, { username: 1, name: 1, role: 1, createdAt: 1, lastActive: 1 })
      .sort({ createdAt: -1 })
      .limit(10);
    
    // Calculate device statistics
    const allUsers = await User.find({}, { deviceTokens: 1 });
    const totalDevices = allUsers.reduce((sum, user) => sum + (user.deviceTokens?.length || 0), 0);
    
    return res.json({
      statistics: {
        users: {
          total: totalUsers,
          owners: totalOwners,
          admins: totalAdmins,
          regular: totalRegularUsers,
          active: activeUsers,
          expired: expiredUsers
        },
        devices: {
          total: totalDevices,
          averagePerUser: totalUsers > 0 ? (totalDevices / totalUsers).toFixed(2) : 0
        },
        cache: cacheStats
      },
      recentUsers: recentUsers.map(user => ({
        username: user.username,
        name: user.name,
        role: user.role,
        createdAt: user.createdAt,
        deviceCount: user.deviceTokens?.length || 0
      })),
      timestamp: new Date().toISOString()
    });
  } catch (err) {
    console.error('Admin stats error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

export default router;