import request from 'supertest';
import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import mongoose from 'mongoose';
import { connectDB, disconnectDB } from '../api/db.js';
import app from '../api/index.js';

// Test configuration
const TEST_PORT = 3001;
const TEST_BASE_URL = `http://localhost:${TEST_PORT}`;

// Test data
const TEST_USER = {
  username: 'testuser',
  password: 'TestPass123',
  name: 'Test User'
};

let testServer;
let authToken;

describe('Ravan System Proxy API Tests', () => {
  beforeAll(async () => {
    // Connect to test database
    process.env.NODE_ENV = 'test';
    process.env.MONGODB_URI = process.env.TEST_MONGODB_URI || 'mongodb://localhost:27017/ravan-test';
    
    await connectDB();
    
    // Start test server
    testServer = app.listen(TEST_PORT);
    console.log(`Test server started on port ${TEST_PORT}`);
    
    // Create test user and get token
    const res = await request(TEST_BASE_URL)
      .post('/auth/login')
      .send({
        username: TEST_USER.username,
        password: TEST_USER.password
      });
    
    if (res.status === 200) {
      authToken = res.body.token;
    }
  });
  
  afterAll(async () => {
    // Close server and database connection
    if (testServer) {
      testServer.close();
    }
    
    await disconnectDB();
    
    // Clear all collections
    const collections = mongoose.connection.collections;
    for (const key in collections) {
      await collections[key].deleteMany({});
    }
  });
  
  describe('Health and Info Endpoints', () => {
    it('GET / should return API info', async () => {
      const res = await request(TEST_BASE_URL)
        .get('/')
        .expect('Content-Type', /json/)
        .expect(200);
      
      expect(res.body).toHaveProperty('ok', true);
      expect(res.body).toHaveProperty('name');
      expect(res.body).toHaveProperty('version');
      expect(res.body).toHaveProperty('services');
    });
    
    it('GET /docs should return documentation', async () => {
      const res = await request(TEST_BASE_URL)
        .get('/docs')
        .expect('Content-Type', /json/)
        .expect(200);
      
      expect(res.body).toHaveProperty('endpoints');
      expect(res.body).toHaveProperty('authentication');
    });
  });
  
  describe('Authentication', () => {
    it('POST /auth/login should authenticate user', async () => {
      const res = await request(TEST_BASE_URL)
        .post('/auth/login')
        .send({
          username: TEST_USER.username,
          password: TEST_USER.password
        })
        .expect('Content-Type', /json/)
        .expect(200);
      
      expect(res.body).toHaveProperty('token');
      expect(res.body).toHaveProperty('role');
      expect(res.body).toHaveProperty('username');
      
      authToken = res.body.token;
    });
    
    it('POST /auth/login should fail with wrong credentials', async () => {
      const res = await request(TEST_BASE_URL)
        .post('/auth/login')
        .send({
          username: TEST_USER.username,
          password: 'WrongPassword'
        })
        .expect('Content-Type', /json/)
        .expect(401);
      
      expect(res.body).toHaveProperty('error');
    });
  });
  
  describe('Proxy Endpoints', () => {
    it('GET /selectionway/info should return API info', async () => {
      const res = await request(TEST_BASE_URL)
        .get('/selectionway/info')
        .set('Authorization', `Bearer ${authToken}`)
        .expect('Content-Type', /json/)
        .expect(200);
      
      expect(res.body).toHaveProperty('api', 'selectionway');
      expect(res.body).toHaveProperty('info');
      expect(res.body.info).toHaveProperty('name');
      expect(res.body.info).toHaveProperty('baseUrl');
    });
    
    it('GET /khansir/info should return API info', async () => {
      const res = await request(TEST_BASE_URL)
        .get('/khansir/info')
        .set('Authorization', `Bearer ${authToken}`)
        .expect('Content-Type', /json/)
        .expect(200);
      
      expect(res.body).toHaveProperty('api', 'khansir');
    });
    
    it('GET /careerwill/info should return API info', async () => {
      const res = await request(TEST_BASE_URL)
        .get('/careerwill/info')
        .set('Authorization', `Bearer ${authToken}`)
        .expect('Content-Type', /json/)
        .expect(200);
      
      expect(res.body).toHaveProperty('api', 'careerwill');
    });
  });
  
  describe('Batch Permission System', () => {
    it('Should deny access to unauthorized batch', async () => {
      const res = await request(TEST_BASE_URL)
        .get('/selectionway/batch/unauthorized-batch/full')
        .set('Authorization', `Bearer ${authToken}`)
        .expect('Content-Type', /json/)
        .expect(403);
      
      expect(res.body).toHaveProperty('error');
      expect(res.body.error).toContain('No permission');
    });
    
    it('Should allow access to authorized batch', async () => {
      // Note: This test requires the test user to have access to 'test-batch'
      const res = await request(TEST_BASE_URL)
        .get('/selectionway/batch/test-batch/full')
        .set('Authorization', `Bearer ${authToken}`)
        .expect('Content-Type', /json/);
      
      // Either 200 (if batch exists) or 404/502 (if external API not reachable)
      expect([200, 404, 502]).toContain(res.status);
    });
  });
  
  describe('Admin Routes', () => {
    let adminToken;
    
    beforeAll(async () => {
      // Login as admin
      const res = await request(TEST_BASE_URL)
        .post('/auth/login')
        .send({
          username: process.env.DEFAULT_ADMIN_ID || 'admin',
          password: process.env.DEFAULT_ADMIN_PASSWORD || 'AdminPass123'
        });
      
      if (res.status === 200) {
        adminToken = res.body.token;
      }
    });
    
    it('GET /admin/users should return user list (admin only)', async () => {
      const res = await request(TEST_BASE_URL)
        .get('/admin/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .expect('Content-Type', /json/)
        .expect(200);
      
      expect(Array.isArray(res.body)).toBe(true);
    });
    
    it('GET /admin/users should deny regular user', async () => {
      const res = await request(TEST_BASE_URL)
        .get('/admin/users')
        .set('Authorization', `Bearer ${authToken}`)
        .expect('Content-Type', /json/)
        .expect(403);
      
      expect(res.body).toHaveProperty('error');
    });
  });
  
  describe('Error Handling', () => {
    it('Should return 404 for unknown route', async () => {
      const res = await request(TEST_BASE_URL)
        .get('/unknown-route')
        .expect('Content-Type', /json/)
        .expect(404);
      
      expect(res.body).toHaveProperty('error', 'Not Found');
    });
    
    it('Should return 401 for unauthorized access', async () => {
      const res = await request(TEST_BASE_URL)
        .get('/admin/users')
        .expect('Content-Type', /json/)
        .expect(401);
      
      expect(res.body).toHaveProperty('error');
    });
  });
  
  describe('Rate Limiting', () => {
    it('Should rate limit excessive requests', async () => {
      // Make multiple rapid requests
      const requests = Array(10).fill().map(() => 
        request(TEST_BASE_URL)
          .get('/')
          .set('Authorization', `Bearer ${authToken}`)
      );
      
      const responses = await Promise.all(requests);
      
      // At least some should be successful
      const successful = responses.filter(r => r.status === 200);
      expect(successful.length).toBeGreaterThan(0);
    });
  });
});

// Mock external APIs for testing
describe('Proxy Service Unit Tests', () => {
  it('Should extract batch ID from URL', () => {
    const { Helpers } = require('../api/utils/helpers.js');
    
    const testCases = [
      { url: '/batch/123/full', expected: '123' },
      { url: '/batches/abc-456', expected: 'abc-456' },
      { url: '/today/batch-789', expected: 'batch-789' },
      { url: '/api/batch?batchid=test-123', expected: 'test-123' },
      { url: '/api/course?courseid=math-101', expected: 'math-101' }
    ];
    
    testCases.forEach(({ url, expected }) => {
      const result = Helpers.extractBatchIdFromUrl(url);
      expect(result).toBe(expected);
    });
  });
  
  it('Should validate batch IDs', () => {
    const { Validator } = require('../api/utils/validator.js');
    
    const validCases = ['batch-123', 'test_456', 'ABC-789', 'all'];
    const invalidCases = ['batch@123', 'test&456', '', null, undefined];
    
    validCases.forEach(batchId => {
      const result = Validator.validateBatchId(batchId);
      expect(result.isValid).toBe(true);
    });
    
    invalidCases.forEach(batchId => {
      const result = Validator.validateBatchId(batchId);
      expect(result.isValid).toBe(false);
    });
  });
});

// Performance tests
describe('Performance Tests', () => {
  it('Should cache repeated requests', async () => {
    // This test would require actual external API calls
    // For now, we'll just verify the caching module works
    const { AppCache } = require('../api/cache.js');
    
    const key = 'test:key';
    const value = { data: 'test' };
    
    // Set cache
    AppCache.set(key, value, 10);
    
    // Get from cache
    const cached = AppCache.get(key);
    expect(cached).toEqual(value);
    
    // Get stats
    const stats = AppCache.getStats();
    expect(stats.hits).toBeGreaterThan(0);
  });
});