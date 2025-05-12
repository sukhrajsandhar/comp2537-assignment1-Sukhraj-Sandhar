require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const { MongoClient } = require('mongodb');
const path = require('path');
const { ObjectId } = require('mongodb');

const app = express();
const port = process.env.PORT || 3000;

app.use(express.urlencoded({ extended: false }));
app.use('/public', express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', './views');

const mongoClient = new MongoClient(`mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`);

let userCollection;

async function start() {
  try {
    await mongoClient.connect();
    const db = mongoClient.db(process.env.MONGODB_DATABASE);
    userCollection = db.collection('users');

    app.use(session({
      secret: process.env.NODE_SESSION_SECRET,
      store: MongoStore.create({
        mongoUrl: `mongodb+srv://${process.env.MONGODB_USER}:${process.env.MONGODB_PASSWORD}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`,
        crypto: { secret: process.env.MONGODB_SESSION_SECRET },
        collectionName: 'sessions',
        ttl: 60 * 60, // 1 hour
        autoRemove: 'native',
        stringify: false
      }),
      resave: true,
      saveUninitialized: false,
      cookie: { maxAge: 3600000 } // 1 hour
    }));

    // Authorization middleware
    const requireAuth = (req, res, next) => {
      if (!req.session.user) {
        return res.redirect('/login');
      }
      next();
    };

    const requireAdmin = (req, res, next) => {
      if (!req.session.user || req.session.user.user_type !== 'admin') {
        return res.status(403).render('error', { 
          message: 'You are not authorized to access this page.',
          user: req.session.user 
        });
      }
      next();
    };

    // Routes
    app.get('/', (req, res) => {
      res.render('index', { user: req.session.user });
    });

    app.get('/signup', (req, res) => {
      if (req.session.user) {
        return res.redirect('/members');
      }
      res.render('signup');
    });

    app.post('/signup', async (req, res) => {
      const { name, email, password } = req.body;
      const schema = Joi.object({
        name: Joi.string().max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().min(5).required()
      });

      const validation = schema.validate({ name, email, password });
      if (validation.error) {
        return res.render('signup', { error: 'Invalid input. Please check your information.' });
      }

      try {
        const existingUser = await userCollection.findOne({ email });
        if (existingUser) {
          return res.render('signup', { error: 'Email already exists. Please use a different email.' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        await userCollection.insertOne({ 
          name, 
          email, 
          password: hashedPassword,
          user_type: 'user' // Default user type
        });
        req.session.user = { name, user_type: 'user' };
        res.redirect('/members');
      } catch (error) {
        console.error('Signup error:', error);
        res.render('signup', { error: 'An error occurred. Please try again.' });
      }
    });

    app.get('/login', (req, res) => {
      if (req.session.user) {
        return res.redirect('/members');
      }
      res.render('login');
    });

    app.post('/login', async (req, res) => {
      const { email, password } = req.body;
      const schema = Joi.object({
        email: Joi.string().email().required(),
        password: Joi.string().min(5).required()
      });

      const validation = schema.validate({ email, password });
      if (validation.error) {
        return res.render('login', { error: 'Invalid input. Please check your information.' });
      }

      try {
        const user = await userCollection.findOne({ email });
        if (!user || !(await bcrypt.compare(password, user.password))) {
          return res.render('login', { error: 'Invalid email or password. Please try again.' });
        }

        req.session.user = { name: user.name, user_type: user.user_type };
        res.redirect('/members');
      } catch (error) {
        console.error('Login error:', error);
        res.render('login', { error: 'An error occurred. Please try again.' });
      }
    });

    app.get('/members', (req, res) => {
      if (!req.session.user) {
        return res.redirect('/');
      }
      res.render('members', { user: req.session.user });
    });

    app.get('/logout', (req, res) => {
      req.session.destroy(() => {
        res.redirect('/');
      });
    });

    // Admin routes
    app.get('/admin', requireAuth, requireAdmin, async (req, res) => {
      try {
        const users = await userCollection.find({}).toArray();
        res.render('admin', { users, user: req.session.user });
      } catch (error) {
        console.error('Admin page error:', error);
        res.status(500).render('error', { 
          message: 'An error occurred while loading the admin page.',
          user: req.session.user 
        });
      }
    });

    app.post('/admin/promote/:userId', requireAuth, requireAdmin, async (req, res) => {
      try {
        const { userId } = req.params;
        await userCollection.updateOne(
          { _id: new ObjectId(userId) },
          { $set: { user_type: 'admin' } }
        );
        res.redirect('/admin');
      } catch (error) {
        console.error('Promote user error:', error);
        res.status(500).render('error', { 
          message: 'An error occurred while promoting the user.',
          user: req.session.user 
        });
      }
    });

    app.post('/admin/demote/:userId', requireAuth, requireAdmin, async (req, res) => {
      try {
        const { userId } = req.params;
        await userCollection.updateOne(
          { _id: new ObjectId(userId) },
          { $set: { user_type: 'user' } }
        );
        res.redirect('/admin');
      } catch (error) {
        console.error('Demote user error:', error);
        res.status(500).render('error', { 
          message: 'An error occurred while demoting the user.',
          user: req.session.user 
        });
      }
    });

    app.use((req, res) => {
      res.status(404).render('404');
    });

    app.listen(port, () => console.log(`Server running on port ${port}`));
  } catch (error) {
    console.error('Server startup error:', error);
    process.exit(1);
  }
}

start();
