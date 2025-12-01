const { getDB } = require('../config/db');

class User {
  constructor(userData) {
    this.username = userData.username;
    this.password = userData.password;
    this.batchIds = userData.batchIds || [];
    this.deviceLimit = userData.deviceLimit || 1;
    this.expiryDate = userData.expiryDate || null;
    this.isActive = userData.isActive !== undefined ? userData.isActive : true;
    this.createdAt = new Date();
    this.loggedInDevices = [];
  }

  static async create(userData) {
    const db = getDB();
    const usersCollection = db.collection('users');
    
    // Check if username already exists
    const existingUser = await usersCollection.findOne({ username: userData.username });
    if (existingUser) {
      throw new Error('Username already exists');
    }

    const newUser = new User(userData);
    const result = await usersCollection.insertOne(newUser);
    return result;
  }

  static async findByUsername(username) {
    const db = getDB();
    const usersCollection = db.collection('users');
    return await usersCollection.findOne({ username });
  }

  static async updateUser(username, updateData) {
    const db = getDB();
    const usersCollection = db.collection('users');
    return await usersCollection.updateOne(
      { username },
      { $set: updateData }
    );
  }

  static async deleteUser(username) {
    const db = getDB();
    const usersCollection = db.collection('users');
    return await usersCollection.deleteOne({ username });
  }

  static async getAllUsers() {
    const db = getDB();
    const usersCollection = db.collection('users');
    return await usersCollection.find({}).toArray();
  }

  static async addLoggedInDevice(username, deviceToken) {
    const db = getDB();
    const usersCollection = db.collection('users');
    
    const user = await this.findByUsername(username);
    if (!user) throw new Error('User not found');

    // If device limit is reached and it's not multi-device
    if (user.deviceLimit !== 'multi' && 
        user.loggedInDevices.length >= user.deviceLimit && 
        !user.loggedInDevices.includes(deviceToken)) {
      throw new Error('DEVICE_LIMIT_REACHED');
    }

    // Add device token if not already present
    if (!user.loggedInDevices.includes(deviceToken)) {
      await usersCollection.updateOne(
        { username },
        { $push: { loggedInDevices: deviceToken } }
      );
    }
  }

  static async removeLoggedInDevice(username, deviceToken) {
    const db = getDB();
    const usersCollection = db.collection('users');
    
    await usersCollection.updateOne(
      { username },
      { $pull: { loggedInDevices: deviceToken } }
    );
  }

  static async validateDevice(username, deviceToken) {
    const user = await this.findByUsername(username);
    if (!user) return false;

    // Multi-device users can login from any device
    if (user.deviceLimit === 'multi') return true;

    // Check if device is in loggedInDevices array
    return user.loggedInDevices.includes(deviceToken);
  }
}

module.exports = User;