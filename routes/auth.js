const express = require('express');
const router = express.Router();
const User = require('../models/User');
const { validateUserSession } = require('../middleware/auth');

// User login with device
router.post('/login_with_device', validateUserSession, async (req, res) => {
  try {
    const { username, password, device_token } = req.body;

    if (!username || !password || !device_token) {
      return res.status(400).json({
        status: 'error',
        message: 'Username, password and device token are required'
      });
    }

    // Find user
    const user = await User.findByUsername(username);
    if (!user) {
      return res.status(404).json({
        status: 'error',
        message: 'User not found'
      });
    }

    // Check if user is active
    if (!user.isActive) {
      return res.status(401).json({
        status: 'error',
        message: 'User account is deactivated'
      });
    }

    // Check expiry date
    if (user.expiryDate && new Date() > new Date(user.expiryDate)) {
      return res.status(401).json({
        status: 'error',
        message: 'User account has expired'
      });
    }

    // Check password
    if (user.password !== password) {
      return res.status(401).json({
        status: 'error',
        message: 'Invalid password'
      });
    }

    // Add device to logged in devices
    try {
      await User.addLoggedInDevice(username, device_token);
    } catch (error) {
      if (error.message === 'DEVICE_LIMIT_REACHED') {
        return res.status(401).json({
          status: 'already_logged_in',
          message: 'Device limit reached. Cannot login from more devices.'
        });
      }
      throw error;
    }

    // Determine login type message
    let loginMessage = 'Single device login successful';
    if (user.deviceLimit === 'multi') {
      loginMessage = 'Multi-device login successful - can login from any device';
    } else if (user.deviceLimit > 1) {
      loginMessage = `${user.deviceLimit} device login successful`;
    }

    res.json({
      status: 'success',
      message: loginMessage,
      allowed_batches: user.batchIds,
      device_limit: user.deviceLimit,
      expiry_date: user.expiryDate
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error during login'
    });
  }
});

// User logout
router.post('/logout', async (req, res) => {
  try {
    const { username, device_token } = req.body;

    if (!username) {
      return res.status(400).json({
        status: 'error',
        message: 'Username is required'
      });
    }

    // Remove device from logged in devices
    if (device_token) {
      await User.removeLoggedInDevice(username, device_token);
    }

    res.json({
      status: 'success',
      message: 'Logout successful'
    });

  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error during logout'
    });
  }
});

// Check user session
router.post('/check_session', async (req, res) => {
  try {
    const { username, device_token } = req.body;

    if (!username || !device_token) {
      return res.status(400).json({
        status: 'error',
        message: 'Username and device token are required'
      });
    }

    const isValid = await User.validateDevice(username, device_token);
    
    if (isValid) {
      res.json({
        status: 'success',
        message: 'Session is valid'
      });
    } else {
      res.status(401).json({
        status: 'error',
        message: 'Session expired or invalid'
      });
    }

  } catch (error) {
    console.error('Session check error:', error);
    res.status(500).json({
      status: 'error',
      message: 'Internal server error during session check'
    });
  }
});

module.exports = router;