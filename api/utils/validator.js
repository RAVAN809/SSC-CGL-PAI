import mongoose from 'mongoose';

// Validation patterns
const PATTERNS = {
  USERNAME: /^[a-zA-Z0-9_]{3,30}$/,
  PASSWORD: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/,
  EMAIL: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  BATCH_ID: /^[a-zA-Z0-9\-_]+$/,
  API_KEY: /^[a-zA-Z0-9]{32,64}$/,
  DEVICE_TOKEN: /^[a-zA-Z0-9\-_]{20,100}$/
};

// Validation error messages
const ERROR_MESSAGES = {
  REQUIRED: (field) => `${field} is required`,
  INVALID: (field) => `Invalid ${field}`,
  TOO_SHORT: (field, min) => `${field} must be at least ${min} characters`,
  TOO_LONG: (field, max) => `${field} must be at most ${max} characters`,
  NOT_FOUND: (field) => `${field} not found`,
  ALREADY_EXISTS: (field) => `${field} already exists`,
  INVALID_TYPE: (field, type) => `${field} must be a ${type}`,
  INVALID_FORMAT: (field) => `Invalid ${field} format`
};

export class Validator {
  // Validate username
  static validateUsername(username) {
    const errors = [];
    
    if (!username) {
      errors.push(ERROR_MESSAGES.REQUIRED('Username'));
      return { isValid: false, errors };
    }
    
    if (typeof username !== 'string') {
      errors.push(ERROR_MESSAGES.INVALID_TYPE('username', 'string'));
    }
    
    if (username.length < 3) {
      errors.push(ERROR_MESSAGES.TOO_SHORT('Username', 3));
    }
    
    if (username.length > 30) {
      errors.push(ERROR_MESSAGES.TOO_LONG('Username', 30));
    }
    
    if (!PATTERNS.USERNAME.test(username)) {
      errors.push('Username can only contain letters, numbers, and underscores');
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      value: username.trim()
    };
  }
  
  // Validate password
  static validatePassword(password, isHashed = false) {
    const errors = [];
    
    if (!password) {
      errors.push(ERROR_MESSAGES.REQUIRED('Password'));
      return { isValid: false, errors };
    }
    
    if (isHashed) {
      // Hashed password validation (for storage)
      if (typeof password !== 'string') {
        errors.push(ERROR_MESSAGES.INVALID_TYPE('password', 'string'));
      }
      
      if (password.length < 60 || password.length > 100) {
        errors.push('Invalid password hash format');
      }
    } else {
      // Plain password validation (for input)
      if (typeof password !== 'string') {
        errors.push(ERROR_MESSAGES.INVALID_TYPE('password', 'string'));
      }
      
      if (password.length < 8) {
        errors.push(ERROR_MESSAGES.TOO_SHORT('Password', 8));
      }
      
      if (!PATTERNS.PASSWORD.test(password)) {
        errors.push('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character');
      }
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      value: password
    };
  }
  
  // Validate batch ID
  static validateBatchId(batchId) {
    const errors = [];
    
    if (!batchId) {
      errors.push(ERROR_MESSAGES.REQUIRED('Batch ID'));
      return { isValid: false, errors };
    }
    
    if (typeof batchId !== 'string') {
      errors.push(ERROR_MESSAGES.INVALID_TYPE('Batch ID', 'string'));
    }
    
    if (!PATTERNS.BATCH_ID.test(batchId)) {
      errors.push(ERROR_MESSAGES.INVALID_FORMAT('Batch ID'));
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      value: batchId.trim()
    };
  }
  
  // Validate batch IDs array
  static validateBatchIds(batchIds) {
    const errors = [];
    const validBatchIds = [];
    
    if (!Array.isArray(batchIds)) {
      errors.push('Batch IDs must be an array');
      return { isValid: false, errors };
    }
    
    for (const batchId of batchIds) {
      const validation = this.validateBatchId(batchId);
      if (validation.isValid) {
        validBatchIds.push(validation.value);
      } else {
        errors.push(`Invalid batch ID: ${batchId}`);
      }
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      value: validBatchIds
    };
  }
  
  // Validate API key
  static validateApiKey(apiKey) {
    const errors = [];
    
    if (!apiKey) {
      errors.push(ERROR_MESSAGES.REQUIRED('API Key'));
      return { isValid: false, errors };
    }
    
    if (typeof apiKey !== 'string') {
      errors.push(ERROR_MESSAGES.INVALID_TYPE('API Key', 'string'));
    }
    
    if (!PATTERNS.API_KEY.test(apiKey)) {
      errors.push(ERROR_MESSAGES.INVALID_FORMAT('API Key'));
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      value: apiKey.trim()
    };
  }
  
  // Validate device token
  static validateDeviceToken(deviceToken) {
    const errors = [];
    
    if (!deviceToken) {
      errors.push(ERROR_MESSAGES.REQUIRED('Device Token'));
      return { isValid: false, errors };
    }
    
    if (typeof deviceToken !== 'string') {
      errors.push(ERROR_MESSAGES.INVALID_TYPE('Device Token', 'string'));
    }
    
    if (!PATTERNS.DEVICE_TOKEN.test(deviceToken)) {
      errors.push(ERROR_MESSAGES.INVALID_FORMAT('Device Token'));
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      value: deviceToken.trim()
    };
  }
  
  // Validate MongoDB ObjectId
  static validateObjectId(id, fieldName = 'ID') {
    const errors = [];
    
    if (!id) {
      errors.push(ERROR_MESSAGES.REQUIRED(fieldName));
      return { isValid: false, errors };
    }
    
    if (!mongoose.Types.ObjectId.isValid(id)) {
      errors.push(ERROR_MESSAGES.INVALID(fieldName));
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      value: id
    };
  }
  
  // Validate date
  static validateDate(dateString, fieldName = 'Date') {
    const errors = [];
    
    if (!dateString) {
      return { isValid: true, errors: [], value: null };
    }
    
    const date = new Date(dateString);
    
    if (isNaN(date.getTime())) {
      errors.push(ERROR_MESSAGES.INVALID(fieldName));
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      value: date
    };
  }
  
  // Validate expiresInMinutes
  static validateExpiresInMinutes(expiresInMinutes) {
    const errors = [];
    
    if (expiresInMinutes === undefined || expiresInMinutes === null) {
      return { isValid: true, errors: [], value: null };
    }
    
    if (typeof expiresInMinutes !== 'number') {
      errors.push(ERROR_MESSAGES.INVALID_TYPE('Expires in minutes', 'number'));
    }
    
    if (expiresInMinutes < 0) {
      errors.push('Expires in minutes cannot be negative');
    }
    
    if (expiresInMinutes > 365 * 24 * 60) { // 1 year max
      errors.push('Expires in minutes cannot exceed 1 year');
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      value: expiresInMinutes
    };
  }
  
  // Validate user creation data
  static validateUserData(data) {
    const errors = [];
    const validatedData = {};
    
    // Validate username
    if (data.username) {
      const usernameValidation = this.validateUsername(data.username);
      if (usernameValidation.isValid) {
        validatedData.username = usernameValidation.value;
      } else {
        errors.push(...usernameValidation.errors);
      }
    } else {
      errors.push(ERROR_MESSAGES.REQUIRED('Username'));
    }
    
    // Validate name
    if (data.name) {
      if (typeof data.name === 'string' && data.name.trim().length >= 2) {
        validatedData.name = data.name.trim();
      } else {
        errors.push('Name must be at least 2 characters');
      }
    } else {
      errors.push(ERROR_MESSAGES.REQUIRED('Name'));
    }
    
    // Validate password
    if (data.password) {
      const passwordValidation = this.validatePassword(data.password);
      if (passwordValidation.isValid) {
        validatedData.password = passwordValidation.value;
      } else {
        errors.push(...passwordValidation.errors);
      }
    } else {
      errors.push(ERROR_MESSAGES.REQUIRED('Password'));
    }
    
    // Validate role
    if (data.role) {
      const validRoles = ['owner', 'admin', 'user'];
      if (validRoles.includes(data.role)) {
        validatedData.role = data.role;
      } else {
        errors.push(`Role must be one of: ${validRoles.join(', ')}`);
      }
    } else {
      errors.push(ERROR_MESSAGES.REQUIRED('Role'));
    }
    
    // Validate allowedBatches (optional)
    if (data.allowedBatches !== undefined) {
      const batchesValidation = this.validateBatchIds(
        Array.isArray(data.allowedBatches) ? data.allowedBatches : [data.allowedBatches]
      );
      if (batchesValidation.isValid) {
        validatedData.allowedBatches = batchesValidation.value;
      } else {
        errors.push(...batchesValidation.errors);
      }
    }
    
    // Validate expiresInMinutes (optional)
    if (data.expiresInMinutes !== undefined) {
      const expiresValidation = this.validateExpiresInMinutes(data.expiresInMinutes);
      if (expiresValidation.isValid) {
        validatedData.expiresInMinutes = expiresValidation.value;
      } else {
        errors.push(...expiresValidation.errors);
      }
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      data: validatedData
    };
  }
  
  // Validate login data
  static validateLoginData(data) {
    const errors = [];
    const validatedData = {};
    
    // Validate username
    if (data.username) {
      const usernameValidation = this.validateUsername(data.username);
      if (usernameValidation.isValid) {
        validatedData.username = usernameValidation.value;
      } else {
        errors.push(...usernameValidation.errors);
      }
    } else {
      errors.push(ERROR_MESSAGES.REQUIRED('Username'));
    }
    
    // Validate password
    if (data.password) {
      if (typeof data.password === 'string' && data.password.length > 0) {
        validatedData.password = data.password;
      } else {
        errors.push(ERROR_MESSAGES.REQUIRED('Password'));
      }
    } else {
      errors.push(ERROR_MESSAGES.REQUIRED('Password'));
    }
    
    // Validate device token (optional)
    if (data.deviceToken) {
      const deviceValidation = this.validateDeviceToken(data.deviceToken);
      if (deviceValidation.isValid) {
        validatedData.deviceToken = deviceValidation.value;
      } else {
        errors.push(...deviceValidation.errors);
      }
    }
    
    // Device info (optional)
    if (data.deviceInfo) {
      if (typeof data.deviceInfo === 'string') {
        validatedData.deviceInfo = data.deviceInfo.trim().substring(0, 200);
      }
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      data: validatedData
    };
  }
  
  // Sanitize input
  static sanitizeInput(input) {
    if (typeof input === 'string') {
      return input.trim().replace(/[<>]/g, '');
    }
    if (Array.isArray(input)) {
      return input.map(item => this.sanitizeInput(item));
    }
    if (typeof input === 'object' && input !== null) {
      const sanitized = {};
      for (const key in input) {
        sanitized[key] = this.sanitizeInput(input[key]);
      }
      return sanitized;
    }
    return input;
  }
}

export default Validator;