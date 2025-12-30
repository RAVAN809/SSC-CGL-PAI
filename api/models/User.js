import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import Validator from '../utils/validator.js';

const UserSchema = new mongoose.Schema(
  {
    username: { 
      type: String, 
      unique: true, 
      required: true, 
      trim: true,
      lowercase: true,
      minlength: 3,
      maxlength: 30,
      validate: {
        validator: function(v) {
          return /^[a-zA-Z0-9_]+$/.test(v);
        },
        message: 'Username can only contain letters, numbers, and underscores'
      }
    },
    name: { 
      type: String, 
      required: true, 
      trim: true,
      minlength: 2,
      maxlength: 100
    },
    role: { 
      type: String, 
      enum: ['owner', 'admin', 'user'], 
      required: true,
      default: 'user'
    },
    passwordHash: { 
      type: String, 
      required: true 
    },
    allowedBatches: { 
      type: [String], 
      default: [],
      validate: {
        validator: function(batches) {
          if (!Array.isArray(batches)) return false;
          
          // Allow "all" as special value
          if (batches.length === 1 && batches[0] === 'all') {
            return true;
          }
          
          // Validate each batch ID
          return batches.every(batch => {
            const validation = Validator.validateBatchId(batch);
            return validation.isValid;
          });
        },
        message: 'Invalid batch IDs. Each batch must be a valid string.'
      }
    },
    expiresAt: { 
      type: Date, 
      default: null,
      index: true
    },
    deviceTokens: [
      {
        token: { 
          type: String, 
          required: true,
          index: true
        },
        deviceInfo: { 
          type: String,
          default: 'Unknown Device',
          maxlength: 200
        },
        loggedInAt: { 
          type: Date, 
          default: Date.now 
        },
        lastActive: { 
          type: Date, 
          default: Date.now 
        },
        ipAddress: {
          type: String,
          default: ''
        },
        userAgent: {
          type: String,
          default: ''
        }
      }
    ],
    lastLogin: {
      type: Date,
      default: null
    },
    loginAttempts: {
      type: Number,
      default: 0
    },
    lockUntil: {
      type: Date,
      default: null
    },
    metadata: {
      createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        default: null
      },
      notes: {
        type: String,
        default: '',
        maxlength: 500
      },
      tags: [{
        type: String,
        maxlength: 50
      }]
    }
  },
  { 
    timestamps: true,
    toJSON: {
      virtuals: true,
      transform: function(doc, ret) {
        delete ret.passwordHash;
        delete ret.deviceTokens;
        delete ret.loginAttempts;
        delete ret.lockUntil;
        return ret;
      }
    },
    toObject: {
      virtuals: true,
      transform: function(doc, ret) {
        delete ret.passwordHash;
        delete ret.deviceTokens;
        delete ret.loginAttempts;
        delete ret.lockUntil;
        return ret;
      }
    }
  }
);

// Virtual for checking if account is expired
UserSchema.virtual('isExpired').get(function() {
  return this.expiresAt && this.expiresAt < new Date();
});

// Virtual for checking if account is active
UserSchema.virtual('isActive').get(function() {
  return !this.isExpired;
});

// Virtual for device count
UserSchema.virtual('deviceCount').get(function() {
  return this.deviceTokens?.length || 0;
});

// Virtual for active device count (active within last 24 hours)
UserSchema.virtual('activeDeviceCount').get(function() {
  const twentyFourHoursAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
  return this.deviceTokens?.filter(d => d.lastActive > twentyFourHoursAgo).length || 0;
});

// Index for faster queries
UserSchema.index({ username: 1, role: 1 });
UserSchema.index({ role: 1, expiresAt: 1 });
UserSchema.index({ 'deviceTokens.token': 1 });
UserSchema.index({ createdAt: -1 });

// Pre-save middleware for validation
UserSchema.pre('save', function(next) {
  // Validate username
  if (this.username) {
    this.username = this.username.toLowerCase().trim();
  }
  
  // Validate name
  if (this.name) {
    this.name = this.name.trim();
  }
  
  // Validate allowedBatches
  if (this.allowedBatches && Array.isArray(this.allowedBatches)) {
    // Remove duplicates
    this.allowedBatches = [...new Set(this.allowedBatches.map(b => b.trim()))];
    
    // If 'all' is present, it should be the only element
    if (this.allowedBatches.includes('all') && this.allowedBatches.length > 1) {
      this.allowedBatches = ['all'];
    }
  }
  
  next();
});

// Pre-save middleware for owners/admins
UserSchema.pre('save', function(next) {
  // Owners and admins automatically get access to all batches
  if ((this.role === 'owner' || this.role === 'admin') && !this.isModified('allowedBatches')) {
    this.allowedBatches = ['all'];
  }
  
  next();
});

// Pre-remove middleware
UserSchema.pre('remove', async function(next) {
  // Prevent removing owner
  if (this.role === 'owner') {
    throw new Error('Cannot remove owner user');
  }
  
  // TODO: Add any cleanup logic here
  // For example, remove user from any related data
  
  next();
});

// Method to check password
UserSchema.methods.checkPassword = async function(password) {
  try {
    return await bcrypt.compare(password, this.passwordHash);
  } catch (error) {
    console.error('Password check error:', error);
    return false;
  }
};

// Method to hash password
UserSchema.methods.hashPassword = async function(password) {
  return await bcrypt.hash(password, 12);
};

// Method to add device token
UserSchema.methods.addDeviceToken = function(token, deviceInfo = '', ipAddress = '', userAgent = '') {
  if (!token) return false;
  
  this.deviceTokens = this.deviceTokens || [];
  
  // Check if device already exists
  const existingDevice = this.deviceTokens.find(d => d.token === token);
  
  if (existingDevice) {
    // Update existing device
    existingDevice.lastActive = new Date();
    existingDevice.deviceInfo = deviceInfo || existingDevice.deviceInfo;
    existingDevice.ipAddress = ipAddress || existingDevice.ipAddress;
    existingDevice.userAgent = userAgent || existingDevice.userAgent;
  } else {
    // Add new device
    this.deviceTokens.push({
      token,
      deviceInfo: deviceInfo.substring(0, 200) || 'Unknown Device',
      loggedInAt: new Date(),
      lastActive: new Date(),
      ipAddress: ipAddress.substring(0, 45) || '',
      userAgent: userAgent.substring(0, 500) || ''
    });
  }
  
  // Update last login
  this.lastLogin = new Date();
  
  return true;
};

// Method to remove device token
UserSchema.methods.removeDeviceToken = function(token) {
  if (!token) return false;
  
  const initialLength = this.deviceTokens.length;
  this.deviceTokens = this.deviceTokens.filter(d => d.token !== token);
  
  return initialLength !== this.deviceTokens.length;
};

// Method to clear all device tokens
UserSchema.methods.clearAllDevices = function() {
  const count = this.deviceTokens.length;
  this.deviceTokens = [];
  return count;
};

// Method to check if user has access to batch
UserSchema.methods.hasBatchAccess = function(batchId) {
  if (!batchId) return false;
  
  // Owners and admins have all access
  if (this.role === 'owner' || this.role === 'admin') {
    return true;
  }
  
  // Check allowed batches
  return this.allowedBatches.includes('all') || this.allowedBatches.includes(batchId);
};

// Method to get active devices
UserSchema.methods.getActiveDevices = function(hours = 24) {
  const cutoffTime = new Date(Date.now() - hours * 60 * 60 * 1000);
  return this.deviceTokens?.filter(d => d.lastActive > cutoffTime) || [];
};

// Method to get user summary
UserSchema.methods.getSummary = function() {
  return {
    id: this._id,
    username: this.username,
    name: this.name,
    role: this.role,
    allowedBatches: this.allowedBatches,
    expiresAt: this.expiresAt,
    isActive: this.isActive,
    isExpired: this.isExpired,
    deviceCount: this.deviceCount,
    activeDeviceCount: this.activeDeviceCount,
    lastLogin: this.lastLogin,
    createdAt: this.createdAt,
    updatedAt: this.updatedAt
  };
};

// Static method to find by username with role
UserSchema.statics.findByUsernameAndRole = function(username, role) {
  return this.findOne({ username: username.toLowerCase(), role });
};

// Static method to get all users with batch access
UserSchema.statics.getUsersWithBatchAccess = function(batchId) {
  return this.find({
    $or: [
      { role: { $in: ['owner', 'admin'] } },
      { allowedBatches: 'all' },
      { allowedBatches: batchId }
    ]
  });
};

// Static method to count users by role
UserSchema.statics.countByRole = function(role) {
  return this.countDocuments({ role });
};

// Static method to get active users
UserSchema.statics.getActiveUsers = function() {
  return this.find({
    $or: [
      { expiresAt: null },
      { expiresAt: { $gt: new Date() } }
    ]
  });
};

// Static method to get expired users
UserSchema.statics.getExpiredUsers = function() {
  return this.find({
    expiresAt: { $lt: new Date() }
  });
};

// Create the model
const User = mongoose.models.User || mongoose.model('User', UserSchema);

export default User;