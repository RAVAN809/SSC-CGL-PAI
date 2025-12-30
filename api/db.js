import mongoose from 'mongoose';

let isConnected = false;
let connectionAttempts = 0;
const MAX_RETRIES = 3;

// Connection events
mongoose.connection.on('connected', () => {
  console.log('✅ MongoDB connected successfully');
  isConnected = true;
  connectionAttempts = 0;
});

mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB connection error:', err.message);
  isConnected = false;
});

mongoose.connection.on('disconnected', () => {
  console.log('⚠️  MongoDB disconnected');
  isConnected = false;
});

mongoose.connection.on('reconnected', () => {
  console.log('🔄 MongoDB reconnected');
  isConnected = true;
});

// Graceful shutdown
process.on('SIGINT', async () => {
  try {
    await mongoose.connection.close();
    console.log('🛑 MongoDB connection closed through app termination');
    process.exit(0);
  } catch (err) {
    console.error('Error closing MongoDB connection:', err);
    process.exit(1);
  }
});

export async function connectDB() {
  // If already connected, return
  if (isConnected && mongoose.connection.readyState === 1) {
    return mongoose.connection;
  }

  // If connecting, wait
  if (mongoose.connection.readyState === 2) {
    console.log('⏳ MongoDB is connecting...');
    return new Promise((resolve, reject) => {
      mongoose.connection.once('connected', () => {
        resolve(mongoose.connection);
      });
      mongoose.connection.once('error', reject);
    });
  }

  const uri = process.env.MONGODB_URI;
  
  if (!uri) {
    throw new Error('❌ MONGODB_URI is not defined in environment variables');
  }

  // Check if URI format is valid
  if (!uri.startsWith('mongodb://') && !uri.startsWith('mongodb+srv://')) {
    throw new Error('❌ Invalid MongoDB URI format');
  }

  // Connection options for serverless environments
  const options = {
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000,
    connectTimeoutMS: 10000,
    maxPoolSize: 10,
    minPoolSize: 2,
    heartbeatFrequencyMS: 10000,
    retryWrites: true,
    w: 'majority'
  };

  // For Vercel/serverless environments
  if (process.env.VERCEL) {
    options.maxPoolSize = 1;
    options.minPoolSize = 0;
  }

  try {
    connectionAttempts++;
    console.log(`🔌 Connecting to MongoDB (attempt ${connectionAttempts}/${MAX_RETRIES})...`);
    
    await mongoose.connect(uri, options);
    
    isConnected = true;
    console.log(`✅ MongoDB connected to: ${mongoose.connection.host}`);
    
    return mongoose.connection;
    
  } catch (error) {
    console.error(`❌ MongoDB connection failed (attempt ${connectionAttempts}):`, error.message);
    
    // Retry logic
    if (connectionAttempts < MAX_RETRIES) {
      console.log(`🔄 Retrying connection in 2 seconds...`);
      await new Promise(resolve => setTimeout(resolve, 2000));
      return connectDB();
    }
    
    throw new Error(`Failed to connect to MongoDB after ${MAX_RETRIES} attempts: ${error.message}`);
  }
}

export async function disconnectDB() {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.connection.close();
    console.log('🔌 MongoDB disconnected');
    isConnected = false;
  }
}

export async function checkDBHealth() {
  try {
    const conn = await connectDB();
    
    // Run a simple query to check health
    const adminDb = conn.db.admin();
    const pingResult = await adminDb.ping();
    
    return {
      status: 'healthy',
      connected: isConnected,
      readyState: conn.readyState,
      ping: pingResult.ok === 1 ? 'success' : 'failed',
      host: conn.host,
      name: conn.name,
      models: Object.keys(mongoose.models),
      timestamp: new Date().toISOString()
    };
  } catch (error) {
    return {
      status: 'unhealthy',
      connected: false,
      error: error.message,
      timestamp: new Date().toISOString()
    };
  }
}

// Export mongoose for direct use if needed
export { mongoose };

// Helper to get connection state
export function getConnectionStatus() {
  const states = {
    0: 'disconnected',
    1: 'connected',
    2: 'connecting',
    3: 'disconnecting',
    99: 'uninitialized'
  };
  
  return {
    isConnected,
    readyState: mongoose.connection.readyState,
    state: states[mongoose.connection.readyState] || 'unknown',
    host: mongoose.connection.host,
    name: mongoose.connection.name
  };
}