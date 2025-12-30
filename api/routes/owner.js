import express from 'express';
import bcrypt from 'bcryptjs';
import User from '../models/User.js';
import { requireAuth, requireRole } from '../middleware/auth.js';
import Validator from '../utils/validator.js';
import AppCache from '../cache.js';

const router = express.Router();

// Owner-only routes
router.use(requireAuth, requireRole('owner'));

// GET /owner/admins - List all admins
router.get('/admins', async (req, res) => {
  try {
    const { 
      page = 1, 
      limit = 50,
      search = '',
      activeOnly = false
    } = req.query;
    
    // Build query
    const query = { role: 'admin' };
    
    // Search functionality
    if (search) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { name: { $regex: search, $options: 'i' } }
      ];
    }
    
    // Active only filter
    if (activeOnly === 'true') {
      query.expiresAt = { $gt: new Date() };
    }
    
    // Calculate pagination
    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(100, Math.max(1, parseInt(limit)));
    const skip = (pageNum - 1) * limitNum;
    
    // Get admins with pagination
    const [admins, total] = await Promise.all([
      User.find(query, { passwordHash: 0 })
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limitNum),
      User.countDocuments(query)
    ]);
    
    // Format admins
    const formattedAdmins = admins.map(admin => ({
      id: admin._id,
      username: admin.username,
      name: admin.name,
      allowedBatches: admin.allowedBatches,
      expiresAt: admin.expiresAt,
      deviceCount: admin.deviceTokens?.length || 0,
      lastActive: admin.deviceTokens?.length > 0 
        ? new Date(Math.max(...admin.deviceTokens.map(d => new Date(d.lastActive).getTime())))
        : null,
      createdAt: admin.createdAt,
      updatedAt: admin.updatedAt,
      isActive: !admin.expiresAt || admin.expiresAt > new Date()
    }));
    
    return res.json({
      admins: formattedAdmins,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        pages: Math.ceil(total / limitNum)
      },
      filters: {
        search,
        activeOnly
      }
    });
  } catch (err) {
    console.error('Owner admins list error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /owner/admins/:username - Get admin details
router.get('/admins/:username', async (req, res) => {
  try {
    const { username } = req.params;
    
    const admin = await User.findOne({ username, role: 'admin' }, { passwordHash: 0 });
    if (!admin) return res.status(404).json({ error: 'Admin not found' });
    
    return res.json({
      id: admin._id,
      username: admin.username,
      name: admin.name,
      allowedBatches: admin.allowedBatches,
      expiresAt: admin.expiresAt,
      deviceTokens: admin.deviceTokens?.map(token => ({
        token: token.token.substring(0, 10) + '...', // Mask token
        deviceInfo: token.deviceInfo,
        loggedInAt: token.loggedInAt,
        lastActive: token.lastActive,
        isActive: (new Date() - new Date(token.lastActive)) < 24 * 60 * 60 * 1000
      })) || [],
      deviceCount: admin.deviceTokens?.length || 0,
      createdAt: admin.createdAt,
      updatedAt: admin.updatedAt,
      isActive: !admin.expiresAt || admin.expiresAt > new Date()
    });
  } catch (err) {
    console.error('Owner admin details error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// POST /owner/admins - Create new admin
router.post('/admins', async (req, res) => {
  try {
    const { username, name, password, allowedBatches, expiresInMinutes } = req.body || {};
    
    // Validate input
    const validation = Validator.validateUserData({
      username,
      name,
      password,
      role: 'admin',
      allowedBatches,
      expiresInMinutes
    });
    
    if (!validation.isValid) {
      return res.status(400).json({ 
        error: 'Validation failed', 
        details: validation.errors 
      });
    }
    
    // Prevent using owner username
    if (username === process.env.OWNER_ID) {
      return res.status(400).json({ error: 'Cannot use owner username for admin' });
    }
    
    // Check if username exists
    const exists = await User.findOne({ username });
    if (exists) {
      return res.status(409).json({ 
        error: 'Username already exists',
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
    
    // Validate batches
    let validBatches = [];
    if (allowedBatches) {
      if (allowedBatches === 'all') {
        validBatches = ['all'];
      } else if (Array.isArray(allowedBatches)) {
        validBatches = allowedBatches.map(b => b.toString().trim()).filter(b => b);
      }
    } else {
      validBatches = ['all']; // Default: admins have access to all batches
    }
    
    // Create admin
    const admin = await User.create({ 
      username, 
      name, 
      role: 'admin', 
      passwordHash,
      allowedBatches: validBatches,
      expiresAt
    });

    // Clear cache
    AppCache.flush();

    return res.status(201).json({
      success: true,
      message: 'Admin created successfully',
      admin: {
        id: admin._id,
        username: admin.username,
        name: admin.name,
        role: admin.role,
        allowedBatches: admin.allowedBatches,
        expiresAt: admin.expiresAt,
        expiresIn: expiresInMinutes ? `${expiresInMinutes} minutes` : 'Never'
      }
    });
  } catch (err) {
    console.error('Owner create admin error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// PUT /owner/admins/:username - Update admin
router.put('/admins/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const { 
      name, 
      allowedBatches, 
      expiresInMinutes,
      password 
    } = req.body || {};
    
    // Find admin
    const admin = await User.findOne({ username, role: 'admin' });
    if (!admin) return res.status(404).json({ error: 'Admin not found' });
    
    // Prevent modifying owner
    if (username === process.env.OWNER_ID) {
      return res.status(400).json({ error: 'Cannot modify owner through admin endpoint' });
    }
    
    // Update name if provided
    if (name) {
      if (typeof name === 'string' && name.trim().length >= 2) {
        admin.name = name.trim();
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
      admin.passwordHash = await bcrypt.hash(password, 12);
    }
    
    // Update batches if provided
    if (allowedBatches !== undefined) {
      if (allowedBatches === 'all') {
        admin.allowedBatches = ['all'];
      } else if (Array.isArray(allowedBatches)) {
        // Validate each batch ID
        const validBatches = [];
        for (const batch of allowedBatches) {
          const validation = Validator.validateBatchId(batch);
          if (validation.isValid) {
            validBatches.push(validation.value);
          }
        }
        admin.allowedBatches = validBatches;
      } else if (allowedBatches === null) {
        admin.allowedBatches = ['all']; // Default for admins
      }
    }
    
    // Update expiry if provided
    if (expiresInMinutes !== undefined) {
      if (expiresInMinutes === null || expiresInMinutes === 0) {
        admin.expiresAt = null;
      } else if (expiresInMinutes > 0) {
        admin.expiresAt = new Date(Date.now() + expiresInMinutes * 60000);
      }
    }
    
    await admin.save();
    
    // Clear cache
    AppCache.clearUserCache(admin._id.toString());

    return res.json({
      success: true,
      message: 'Admin updated successfully',
      admin: {
        username: admin.username,
        name: admin.name,
        allowedBatches: admin.allowedBatches,
        expiresAt: admin.expiresAt,
        deviceCount: admin.deviceTokens?.length || 0,
        updatedAt: admin.updatedAt
      }
    });
  } catch (err) {
    console.error('Owner update admin error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /owner/admins/:username - Delete admin
router.delete('/admins/:username', async (req, res) => {
  try {
    const { username } = req.params;
    
    // Prevent deleting owner
    if (username === process.env.OWNER_ID) {
      return res.status(400).json({ error: 'Owner cannot be removed' });
    }
    
    const admin = await User.findOne({ username, role: 'admin' });
    if (!admin) return res.status(404).json({ error: 'Admin not found' });
    
    await User.deleteOne({ _id: admin._id });
    
    // Clear cache
    AppCache.clearUserCache(admin._id.toString());

    return res.json({
      success: true,
      message: 'Admin deleted successfully',
      deletedAdmin: {
        username: admin.username,
        name: admin.name
      }
    });
  } catch (err) {
    console.error('Owner delete admin error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /owner/all-users - View all users with details
router.get('/all-users', async (req, res) => {
  try {
    const { 
      role = 'all', 
      page = 1, 
      limit = 100,
      search = '',
      sortBy = 'role',
      sortOrder = 'asc',
      activeOnly = false
    } = req.query;
    
    // Build query
    const query = {};
    
    // Role filter
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
    
    // Active only filter
    if (activeOnly === 'true') {
      query.$or = [
        { expiresAt: null },
        { expiresAt: { $gt: new Date() } }
      ];
    }
    
    // Calculate pagination
    const pageNum = Math.max(1, parseInt(page));
    const limitNum = Math.min(200, Math.max(1, parseInt(limit)));
    const skip = (pageNum - 1) * limitNum;
    
    // Build sort
    const sort = {};
    if (sortBy === 'role') {
      // Custom sort for roles: owner -> admin -> user
      sort.roleOrder = 1;
    } else {
      sort[sortBy] = sortOrder === 'asc' ? 1 : -1;
    }
    
    // Get users with aggregation for role ordering
    const users = await User.aggregate([
      { $match: query },
      {
        $addFields: {
          roleOrder: {
            $switch: {
              branches: [
                { case: { $eq: ["$role", "owner"] }, then: 1 },
                { case: { $eq: ["$role", "admin"] }, then: 2 },
                { case: { $eq: ["$role", "user"] }, then: 3 }
              ],
              default: 4
            }
          }
        }
      },
      { $sort: sort },
      { $skip: skip },
      { $limit: limitNum },
      {
        $project: {
          passwordHash: 0,
          deviceTokens: 0,
          roleOrder: 0
        }
      }
    ]);
    
    // Get total count
    const total = await User.countDocuments(query);
    
    // Format users
    const formattedUsers = users.map(user => {
      const now = new Date();
      const lastActive = user.deviceTokens?.length > 0 
        ? new Date(Math.max(...user.deviceTokens.map(d => new Date(d.lastActive).getTime())))
        : null;
      
      return {
        id: user._id,
        username: user.username,
        name: user.name,
        role: user.role,
        allowedBatches: user.allowedBatches,
        expiresAt: user.expiresAt,
        deviceCount: user.deviceTokens?.length || 0,
        lastActive,
        activeMinutes: lastActive ? Math.round((now - lastActive) / 60000) : null,
        isActive: !user.expiresAt || user.expiresAt > now,
        createdAt: user.createdAt,
        updatedAt: user.updatedAt
      };
    });
    
    return res.json({
      users: formattedUsers,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        pages: Math.ceil(total / limitNum)
      },
      statistics: {
        total,
        owners: await User.countDocuments({ role: 'owner' }),
        admins: await User.countDocuments({ role: 'admin' }),
        regularUsers: await User.countDocuments({ role: 'user' }),
        activeUsers: await User.countDocuments({ 
          $or: [
            { expiresAt: null },
            { expiresAt: { $gt: new Date() } }
          ]
        }),
        expiredUsers: await User.countDocuments({ 
          expiresAt: { $lt: new Date() } 
        })
      },
      filters: {
        role,
        search,
        sortBy,
        sortOrder,
        activeOnly
      }
    });
  } catch (err) {
    console.error('Owner all-users error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// GET /owner/system-stats - Get system statistics
router.get('/system-stats', async (req, res) => {
  try {
    const [
      totalUsers,
      totalOwners,
      totalAdmins,
      totalRegularUsers,
      activeUsers,
      expiredUsers,
      cacheStats,
      usersByDay
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ role: 'owner' }),
      User.countDocuments({ role: 'admin' }),
      User.countDocuments({ role: 'user' }),
      User.countDocuments({ 
        $or: [
          { expiresAt: null },
          { expiresAt: { $gt: new Date() } }
        ]
      }),
      User.countDocuments({ expiresAt: { $lt: new Date() } }),
      AppCache.getStats(),
      // Users created in last 7 days
      User.aggregate([
        {
          $match: {
            createdAt: { $gte: new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) }
          }
        },
        {
          $group: {
            _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
            count: { $sum: 1 }
          }
        },
        { $sort: { _id: 1 } }
      ])
    ]);
    
    // Device statistics
    const allUsers = await User.find({}, { deviceTokens: 1 });
    const totalDevices = allUsers.reduce((sum, user) => sum + (user.deviceTokens?.length || 0), 0);
    
    // Recent activity
    const recentActivity = await User.aggregate([
      { $unwind: "$deviceTokens" },
      { $sort: { "deviceTokens.lastActive": -1 } },
      { $limit: 10 },
      {
        $project: {
          username: 1,
          name: 1,
          role: 1,
          deviceInfo: "$deviceTokens.deviceInfo",
          lastActive: "$deviceTokens.lastActive",
          loggedInAt: "$deviceTokens.loggedInAt"
        }
      }
    ]);
    
    return res.json({
      success: true,
      timestamp: new Date().toISOString(),
      statistics: {
        users: {
          total: totalUsers,
          owners: totalOwners,
          admins: totalAdmins,
          regular: totalRegularUsers,
          active: activeUsers,
          expired: expiredUsers,
          activePercentage: totalUsers > 0 ? ((activeUsers / totalUsers) * 100).toFixed(2) : 0
        },
        devices: {
          total: totalDevices,
          averagePerUser: totalUsers > 0 ? (totalDevices / totalUsers).toFixed(2) : 0
        },
        cache: cacheStats,
        growth: {
          last7Days: usersByDay
        }
      },
      recentActivity: recentActivity.map(activity => ({
        username: activity.username,
        name: activity.name,
        role: activity.role,
        deviceInfo: activity.deviceInfo,
        lastActive: activity.lastActive,
        loggedInAt: activity.loggedInAt,
        activeMinutes: Math.round((new Date() - new Date(activity.lastActive)) / 60000)
      })),
      systemInfo: {
        version: '4.0.0',
        nodeVersion: process.version,
        uptime: process.uptime(),
        memoryUsage: process.memoryUsage(),
        environment: process.env.NODE_ENV
      }
    });
  } catch (err) {
    console.error('Owner system stats error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// POST /owner/clear-cache - Clear application cache
router.post('/clear-cache', async (req, res) => {
  try {
    const { cacheType = 'all' } = req.body || {};
    
    let cleared = 0;
    let message = '';
    
    switch (cacheType) {
      case 'all':
        AppCache.flush();
        cleared = AppCache.getStats().totalKeys || 0;
        message = 'Cleared all cache';
        break;
        
      case 'user':
        const userKeys = AppCache.cache.keys().filter(key => key.startsWith('user:'));
        userKeys.forEach(key => AppCache.delete(key));
        cleared = userKeys.length;
        message = `Cleared ${cleared} user cache entries`;
        break;
        
      case 'batch':
        const batchKeys = AppCache.cache.keys().filter(key => key.startsWith('batch:'));
        batchKeys.forEach(key => AppCache.delete(key));
        cleared = batchKeys.length;
        message = `Cleared ${cleared} batch cache entries`;
        break;
        
      case 'api':
        const apiKeys = AppCache.cache.keys().filter(key => key.startsWith('api:'));
        apiKeys.forEach(key => AppCache.delete(key));
        cleared = apiKeys.length;
        message = `Cleared ${cleared} API cache entries`;
        break;
        
      default:
        return res.status(400).json({ 
          error: 'Invalid cache type',
          validTypes: ['all', 'user', 'batch', 'api'] 
        });
    }
    
    return res.json({
      success: true,
      message,
      cleared,
      cacheType,
      remaining: AppCache.getStats().totalKeys
    });
  } catch (err) {
    console.error('Owner clear cache error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// POST /owner/reset-user/:username - Reset user password and devices
router.post('/reset-user/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const { newPassword, clearDevices = false } = req.body || {};
    
    const user = await User.findOne({ username });
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    // Reset password if provided
    if (newPassword) {
      const passwordValidation = Validator.validatePassword(newPassword);
      if (!passwordValidation.isValid) {
        return res.status(400).json({ 
          error: 'Invalid password', 
          details: passwordValidation.errors 
        });
      }
      user.passwordHash = await bcrypt.hash(newPassword, 12);
    }
    
    // Clear devices if requested
    if (clearDevices) {
      const deviceCount = user.deviceTokens?.length || 0;
      user.deviceTokens = [];
      await user.save();
      
      // Clear user cache
      AppCache.clearUserCache(user._id.toString());
      
      return res.json({
        success: true,
        message: `User reset successfully. Cleared ${deviceCount} device(s).`,
        user: {
          username: user.username,
          name: user.name,
          role: user.role,
          passwordReset: !!newPassword,
          devicesCleared: deviceCount
        }
      });
    }
    
    await user.save();
    
    // Clear user cache
    AppCache.clearUserCache(user._id.toString());
    
    return res.json({
      success: true,
      message: 'User reset successfully',
      user: {
        username: user.username,
        name: user.name,
        role: user.role,
        passwordReset: !!newPassword
      }
    });
  } catch (err) {
    console.error('Owner reset user error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

export default router;