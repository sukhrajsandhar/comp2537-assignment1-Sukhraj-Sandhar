require('dotenv').config();
const { MongoClient } = require('mongodb');
const bcrypt = require('bcrypt');

async function createAdminUser() {
  const mongoClient = new MongoClient(`mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`);

  try {
    await mongoClient.connect();
    const db = mongoClient.db(process.env.MONGODB_DATABASE);
    const userCollection = db.collection('users');

    // Check if admin user already exists
    const existingAdmin = await userCollection.findOne({ email: 'admin@example.com' });
    if (existingAdmin) {
      console.log('Admin user already exists');
      return;
    }

    // Create admin user
    const hashedPassword = await bcrypt.hash('admin123', 10);
    await userCollection.insertOne({
      name: 'Admin',
      email: 'admin@example.com',
      password: hashedPassword,
      user_type: 'admin'
    });

    console.log('Admin user created successfully');
  } catch (error) {
    console.error('Error creating admin user:', error);
  } finally {
    await mongoClient.close();
  }
}

createAdminUser(); 