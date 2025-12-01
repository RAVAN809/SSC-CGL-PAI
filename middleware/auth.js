const User = require('../models/User');

const authenticateAdmin = (req, res, next) => {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Basic ')) {
    return res.status(401).json({ 
      status: 'error', 
      message: 'Admin authentication required' 
    });
  }

  const base64Credentials = authHeader.split(' ')[1];
  const credentials = Buffer.from(base64Credentials, 'base64').toString('ascii');
  const [username, password] = credentials.split(':');

  // Hardcoded admin credentials as per requirement
  if (username === 'JASWANT' && password === 'VISHAL') {
    next();
  } else {
    res.status(401).json({ 
      status: 'error', 
      message: 'Invalid admin credentials' 
    });
  }
};

const validateUserSession = async (req, res, next) => {
  try {
    const { username, device_token } = req.body;
    
    if (!username || !device_token) {
      return res.status(400).json({
        status: 'error',
        message: 'Username and device token are required'
      });
    }

    const isValid = await User.validateDevice(username, device_token);
    if (!isValid) {
      return res.status(401).json({
        status: 'already_logged_in',
        message: 'This account is already logged in on another device'
      });
    }

    next();
  } catch (error) {
    res.status(500).json({
      status: 'error',
      message: 'Session validation failed'
    });
  }
};

module.exports = { authenticateAdmin, validateUserSession };