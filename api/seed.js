import bcrypt from 'bcryptjs';
import User from './models/User.js';

export async function ensureSeed() {
  console.log('🔧 Checking seed data...');
  
  const ownerId = process.env.OWNER_ID || 'owner';
  const ownerPass = process.env.OWNER_PASSWORD || 'ChangeMe123';
  const ownerName = process.env.OWNER_NAME || 'System Owner';

  const adminId = process.env.DEFAULT_ADMIN_ID || 'admin';
  const adminPass = process.env.DEFAULT_ADMIN_PASSWORD || 'AdminPass123';
  const adminName = process.env.DEFAULT_ADMIN_NAME || 'System Admin';

  // Validate environment variables
  const missingVars = [];
  if (!process.env.MONGODB_URI) missingVars.push('MONGODB_URI');
  if (!process.env.JWT_SECRET) missingVars.push('JWT_SECRET');
  
  if (missingVars.length > 0) {
    console.warn(`⚠️  Missing environment variables: ${missingVars.join(', ')}`);
  }

  try {
    // Ensure Owner exists
    let existingOwner = await User.findOne({ username: ownerId, role: 'owner' });
    if (!existingOwner) {
      console.log(`👑 Creating owner: ${ownerId}`);
      const ownerHash = await bcrypt.hash(ownerPass, 12);
      existingOwner = await User.create({
        username: ownerId,
        name: ownerName,
        role: 'owner',
        passwordHash: ownerHash,
        allowedBatches: ['all'],
        expiresAt: null
      });
      console.log(`✅ Owner created: ${existingOwner.username}`);
    } else {
      console.log(`✅ Owner exists: ${existingOwner.username}`);
    }

    // Ensure default Admin exists
    let existingAdmin = await User.findOne({ username: adminId, role: 'admin' });
    if (!existingAdmin) {
      console.log(`👨‍💼 Creating admin: ${adminId}`);
      const adminHash = await bcrypt.hash(adminPass, 12);
      existingAdmin = await User.create({
        username: adminId,
        name: adminName,
        role: 'admin',
        passwordHash: adminHash,
        allowedBatches: ['all'],
        expiresAt: null
      });
      console.log(`✅ Admin created: ${existingAdmin.username}`);
    } else {
      console.log(`✅ Admin exists: ${existingAdmin.username}`);
    }

    // Create test user if in development
    if (process.env.NODE_ENV === 'development') {
      const testUserId = 'testuser';
      const testUserPass = 'TestPass123';
      const testUserName = 'Test User';
      
      let existingTestUser = await User.findOne({ username: testUserId, role: 'user' });
      if (!existingTestUser) {
        console.log(`👤 Creating test user: ${testUserId}`);
        const userHash = await bcrypt.hash(testUserPass, 12);
        existingTestUser = await User.create({
          username: testUserId,
          name: testUserName,
          role: 'user',
          passwordHash: userHash,
          allowedBatches: ['batch1', 'batch2', 'test-batch'],
          expiresAt: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) // 30 days from now
        });
        console.log(`✅ Test user created with batches: ${existingTestUser.allowedBatches.join(', ')}`);
      }
    }

    console.log('✅ Seed data check completed');
    return {
      owner: existingOwner.username,
      admin: existingAdmin.username,
      timestamp: new Date().toISOString()
    };

  } catch (error) {
    console.error('❌ Seed error:', error);
    throw new Error(`Seed failed: ${error.message}`);
  }
}

// Function to reset seed (for testing)
export async function resetSeed() {
  try {
    // Delete all users except owner and admin
    const ownerId = process.env.OWNER_ID || 'owner';
    const adminId = process.env.DEFAULT_ADMIN_ID || 'admin';
    
    const result = await User.deleteMany({
      username: { $nin: [ownerId, adminId] }
    });
    
    console.log(`🧹 Reset seed: Deleted ${result.deletedCount} users`);
    return result;
  } catch (error) {
    console.error('Reset seed error:', error);
    throw error;
  }
}