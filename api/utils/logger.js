import winston from 'winston';
import 'winston-daily-rotate-file';
import path from 'path';

const LOG_DIR = process.env.LOG_DIR || 'logs';
const LOG_LEVEL = process.env.LOG_LEVEL || 'info';
const NODE_ENV = process.env.NODE_ENV || 'development';

// Define log format
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.splat(),
  winston.format.json()
);

// Console format for development
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: 'HH:mm:ss' }),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let log = `${timestamp} [${level}]: ${message}`;
    
    if (Object.keys(meta).length > 0) {
      // Don't log stack trace in console for readability
      const { stack, ...restMeta } = meta;
      if (Object.keys(restMeta).length > 0) {
        log += ` ${JSON.stringify(restMeta)}`;
      }
    }
    
    return log;
  })
);

// Create transports
const transports = [];

// Console transport for all environments
transports.push(
  new winston.transports.Console({
    format: consoleFormat,
    level: NODE_ENV === 'development' ? 'debug' : LOG_LEVEL
  })
);

// File transports for production
if (NODE_ENV === 'production') {
  // Daily rotate file for all logs
  transports.push(
    new winston.transports.DailyRotateFile({
      filename: path.join(LOG_DIR, 'application-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '30d',
      format: logFormat,
      level: LOG_LEVEL
    })
  );
  
  // Error logs separately
  transports.push(
    new winston.transports.DailyRotateFile({
      filename: path.join(LOG_DIR, 'error-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '90d',
      format: logFormat,
      level: 'error'
    })
  );
  
  // Proxy/Access logs
  transports.push(
    new winston.transports.DailyRotateFile({
      filename: path.join(LOG_DIR, 'proxy-%DATE%.log'),
      datePattern: 'YYYY-MM-DD',
      zippedArchive: true,
      maxSize: '20m',
      maxFiles: '30d',
      format: logFormat,
      level: 'info'
    })
  );
}

// Create logger instance
const logger = winston.createLogger({
  level: LOG_LEVEL,
  format: logFormat,
  defaultMeta: { service: 'ravan-system' },
  transports,
  exceptionHandlers: [
    new winston.transports.File({ 
      filename: path.join(LOG_DIR, 'exceptions.log') 
    })
  ],
  rejectionHandlers: [
    new winston.transports.File({ 
      filename: path.join(LOG_DIR, 'rejections.log') 
    })
  ]
});

// Logging helper methods
export class AppLogger {
  // Request logging middleware
  static requestLogger(req, res, next) {
    const startTime = Date.now();
    
    // Log after response is sent
    res.on('finish', () => {
      const duration = Date.now() - startTime;
      const logData = {
        method: req.method,
        url: req.originalUrl,
        status: res.statusCode,
        duration: `${duration}ms`,
        ip: req.ip,
        userAgent: req.get('user-agent'),
        userId: req.user?.username || 'anonymous',
        apiName: req.apiName || 'internal'
      };
      
      if (res.statusCode >= 400) {
        logger.warn('Request failed', logData);
      } else {
        logger.info('Request completed', logData);
      }
    });
    
    next();
  }
  
  // Proxy request logging
  static logProxyRequest(apiName, targetUrl, status, duration, fromCache = false) {
    logger.info('Proxy request', {
      apiName,
      targetUrl,
      status,
      duration: `${duration}ms`,
      fromCache
    });
  }
  
  // Proxy error logging
  static logProxyError(apiName, targetUrl, error, duration) {
    logger.error('Proxy error', {
      apiName,
      targetUrl,
      error: error.message,
      status: error.status,
      duration: `${duration}ms`
    });
  }
  
  // Authentication logging
  static logAuth(action, username, success, ip) {
    const level = success ? 'info' : 'warn';
    logger.log(level, 'Authentication', {
      action,
      username,
      success,
      ip
    });
  }
  
  // Batch permission logging
  static logBatchAccess(userId, batchId, granted, endpoint) {
    logger.info('Batch access', {
      userId,
      batchId,
      granted,
      endpoint
    });
  }
  
  // Error logging with context
  static logError(error, context = {}) {
    logger.error('Application error', {
      error: error.message,
      stack: error.stack,
      ...context
    });
  }
  
  // Debug logging (only in development)
  static debug(message, data = {}) {
    if (NODE_ENV === 'development') {
      logger.debug(message, data);
    }
  }
  
  // Get logger instance
  static getLogger() {
    return logger;
  }
}

export default AppLogger;