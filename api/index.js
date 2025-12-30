import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import morgan from 'morgan';
import { connectDB } from './db.js';
import { ensureSeed } from './seed.js';
import { createRateLimiter } from './middleware/rateLimit.js';
import { errorHandler, notFoundHandler } from './middleware/errorHandler.js';

import authRoutes from './routes/auth.js';
import ownerRoutes from './routes/owner.js';
import adminRoutes from './routes/admin.js';
import proxyRoutes from './routes/proxy.js';

const app = express();

// Middleware
app.use(cors({ 
  origin: process.env.CORS_ORIGIN?.split(',') || '*', 
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-device-token', 'x-api-key', 'x-proxy-source']
}));

app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(morgan('dev'));

// Rate limiting
app.use(createRateLimiter());

// Health endpoint
app.get('/', (req, res) => {
  res.json({ 
    ok: true, 
    name: 'Ravan System - Universal Proxy API', 
    version: '4.0.0',
    description: 'Single gateway for multiple educational APIs with RBAC',
    services: {
      auth: '/auth/*',
      admin: '/admin/*',
      owner: '/owner/*',
      apis: {
        selectionway: '/selectionway/*',
        rwawebfree: '/rwawebfree/*',
        spidyrwa: '/spidyrwa/*',
        kgs: '/kgs/*',
        Utkarsh: '/Utkarsh/*',
        khansir: '/khansir/*',
        careerwill: '/careerwill/*',
        CwVideo: '/CwVideo/*'
      }
    },
    endpoints: 'Auto-discovered from external APIs'
  });
});

// API documentation
app.get('/docs', (req, res) => {
  res.json({
    endpoints: {
      'GET /selectionway/batches': 'Get all batches',
      'GET /selectionway/batch/:id/full': 'Get full batch details',
      'GET /selectionway/batch/:id/today': 'Get today\'s batch content',
      'GET /rwawebfree/proxy?endpoint=...': 'Proxy RWA Web Free API',
      'GET /khansir/today/:batch_id': 'Get today\'s Khan Sir batch',
      'GET /khansir/lesson/:lesson_id': 'Get Khan Sir lesson',
      'GET /careerwill/batch?batchid=...': 'Get Career Will batch',
      'GET /careerwill/batch/:batch_id': 'Get batch by ID',
      'GET /CwVideo/get_video_details?name=...': 'Get video details'
    },
    authentication: 'Bearer token or x-api-key header required',
    batchPermissions: 'Users only see batches they have access to'
  });
});

// Attach routes
app.use('/auth', authRoutes);
app.use('/owner', ownerRoutes);
app.use('/admin', adminRoutes);

// Proxy routes
app.use('/selectionway', proxyRoutes);
app.use('/rwawebfree', proxyRoutes);
app.use('/spidyrwa', proxyRoutes);
app.use('/kgs', proxyRoutes);
app.use('/Utkarsh', proxyRoutes);
app.use('/khansir', proxyRoutes);
app.use('/careerwill', proxyRoutes);
app.use('/CwVideo', proxyRoutes);

// 404 handler
app.use(notFoundHandler);

// Error handler
app.use(errorHandler);

// Vercel serverless handler
export default async function handler(req, res) {
  try {
    await connectDB();
    await ensureSeed();
    return app(req, res);
  } catch (err) {
    console.error('Startup error:', err);
    res.status(500).json({ 
      error: 'Startup error', 
      detail: process.env.NODE_ENV === 'development' ? err.message : 'Internal server error'
    });
  }
}

// For local development
if (process.env.NODE_ENV !== 'production') {
  const PORT = process.env.PORT || 3000;
  const server = app.listen(PORT, async () => {
    try {
      await connectDB();
      await ensureSeed();
      console.log(`🚀 Ravan System API running on http://localhost:${PORT}`);
      console.log(`📡 Proxying ${Object.keys(API_CONFIGS).length} external APIs`);
      console.log(`🔐 RBAC Authentication enabled`);
    } catch (error) {
      console.error('Failed to start server:', error);
      process.exit(1);
    }
  });

  // Graceful shutdown
  process.on('SIGTERM', () => {
    console.log('SIGTERM received. Closing server...');
    server.close(() => {
      console.log('Server closed');
      process.exit(0);
    });
  });
}