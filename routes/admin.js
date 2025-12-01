const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { authenticateAdmin } = require('../middleware/auth');

// Get all users
router.get('/users', authenticateAdmin, async (req, res) => {
  try {
    const users = await User.getAllUsers();
    
    // Remove passwords from response for security
    const sanitizedUsers = users.map(user => ({
      username: user.username,
      batchIds: user.batchIds,
      deviceLimit: user.deviceLimit,
      expiryDate: user.expiryDate,
      isActive: user.isActive,
      createdAt: user.createdAt,
      loggedInDevices: user.loggedInDevices
    }));

    res.json({
      status: 'success',
      data: sanitizedUsers
    });

  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to fetch users'
    });
  }
});

// Create new user
router.post('/users', authenticateAdmin, async (req, res) => {
  try {
    const { username, password, batchIds, deviceLimit, expiryDate } = req.body;

    if (!username || !password) {
      return res.status(400).json({
        status: 'error',
        message: 'Username and password are required'
      });
    }

    const userData = {
      username,
      password,
      batchIds: batchIds || [],
      deviceLimit: deviceLimit || 1,
      expiryDate: expiryDate || null,
      isActive: true
    };

    await User.create(userData);

    res.json({
      status: 'success',
      message: 'User created successfully',
      user: {
        username,
        batchIds: userData.batchIds,
        deviceLimit: userData.deviceLimit,
        expiryDate: userData.expiryDate
      }
    });

  } catch (error) {
    console.error('Create user error:', error);
    
    if (error.message === 'Username already exists') {
      return res.status(400).json({
        status: 'error',
        message: error.message
      });
    }

    res.status(500).json({
      status: 'error',
      message: 'Failed to create user'
    });
  }
});

// Update user
router.put('/users/:username', authenticateAdmin, async (req, res) => {
  try {
    const { username } = req.params;
    const { password, batchIds, deviceLimit, expiryDate, isActive } = req.body;

    const updateData = {};
    if (password) updateData.password = password;
    if (batchIds) updateData.batchIds = batchIds;
    if (deviceLimit !== undefined) updateData.deviceLimit = deviceLimit;
    if (expiryDate !== undefined) updateData.expiryDate = expiryDate;
    if (isActive !== undefined) updateData.isActive = isActive;

    const result = await User.updateUser(username, updateData);

    if (result.matchedCount === 0) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }

    res.json({
      status: 'success',
      message: 'User updated successfully'
    });

  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to update user'
    });
  }
});

// Delete user
router.delete('/users/:username', authenticateAdmin, async (req, res) => {
  try {
    const { username } = req.params;

    const result = await User.deleteUser(username);

    if (result.deletedCount === 0) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }

    res.json({
      status: 'success',
      message: 'User deleted successfully'
    });

  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to delete user'
    });
  }
});

// Force logout user from all devices
router.post('/users/:username/force_logout', authenticateAdmin, async (req, res) => {
  try {
    const { username } = req.params;

    const result = await User.updateUser(username, { loggedInDevices: [] });

    if (result.matchedCount === 0) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }

    res.json({
      status: 'success',
      message: 'User logged out from all devices successfully'
    });

  } catch (error) {
    console.error('Force logout error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Failed to force logout user'
    });
  }
});

module.exports = router;