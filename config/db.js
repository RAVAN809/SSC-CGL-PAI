const { MongoClient } = require('mongodb');

const uri = "mongodb+srv://RAVAN_09:Vishal06@cluster0.uzafnxb.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0";

let client;
let database;

const connectDB = async () => {
  try {
    client = new MongoClient(uri);
    await client.connect();
    database = client.db('user_management');
    console.log('MongoDB Connected Successfully');
    return database;
  } catch (error) {
    console.error('MongoDB Connection Error:', error);
    process.exit(1);
  }
};

const getDB = () => {
  if (!database) {
    throw new Error('Database not initialized');
  }
  return database;
};

const closeDB = async () => {
  if (client) {
    await client.close();
  }
};

module.exports = { connectDB, getDB, closeDB };