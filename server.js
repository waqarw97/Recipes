// Importing the necessary dependencies
require('dotenv').config();
const bcrypt = require('bcrypt');
const express = require('express');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const { MongoClient, ObjectId } = require('mongodb');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { body, validationResult } = require('express-validator');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');

const app = express();
const port = process.env.PORT || 3000;

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use('/private', express.static(path.join(__dirname, 'private')));
app.use(morgan('dev'));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: MongoStore.create({
    mongoUrl: process.env.MONGODB_URL,
    collectionName: 'sessions',
    autoRemove: 'interval',
    autoRemoveInterval: 10
  }),
  cookie: {
    secure: false,
    httpOnly: true, 
  }
}));
// Create rate limiter: maximum of 5 requests per minute for the login and registration routes
const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 5,
  message: "Too many requests from this IP, please try again in a minute.",
});
app.use(helmet());

app.use(async (req, res, next) => {
  if (!req.session.userId) {
    next();
    return;
  }

  try {
    const user = await db.collection('users').findOne({ _id: new ObjectId(req.session.userId) }, { projection: { password: 0 } });
    if (user) {
      req.user = user;
    } else {
      delete req.session.userId;
    }
  } catch (err) {
    console.error('Error occurred when loading user: ', err);
  }

  next();
});


function requireLogin(req, res, next) {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.redirect('/login');
  }
}

function ensureAuthenticatedAPI(req, res, next) {
  if (req.session.userId) {
    return next();
  } else {
    return res.status(401).json({ errors: [{ msg: 'User is not authenticated' }] });
  }
}

const mongodb_url = process.env.MONGODB_URL;
let db;

MongoClient.connect(mongodb_url, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(client => {
    console.log('Connected to Database')
    db = client.db('Recipe-DB')
  })
  .catch(error => {
    console.error('An error occurred connecting to MongoDB: ', error);
    process.exit(1);
});

// Root endpoint
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Endpoint to serve the profile page
app.get('/profile', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'private', 'profile.html'));
});

// Endpoint to serve the username change page
app.get('/changeUsername', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'private', 'changeUsername.html'));
});

// Endpoint to serve the email change page
app.get('/changeEmail', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'private', 'changeEmail.html'));
});

// Endpoint to serve the password change page
app.get('/changePassword', requireLogin, (req, res) => {
  res.sendFile(path.join(__dirname, 'private', 'changePassword.html'));
});
// Setting up the '/login' route to handle POST requests
app.post('/login', limiter,

// Validation middleware: Ensure 'username' and 'password' fields are not empty.
body('username').notEmpty().withMessage('Username or email is required'),
body('password').notEmpty().withMessage('Password is required'),

// Request handler: Handles the login logic.
async (req, res) => {

  // Extract validation errors from the request
  const errors = validationResult(req);

  // If validation errors exist, send a 400 Bad Request response with the error messages
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    // Find a user with a matching username or email
    const user = await db.collection('users').findOne({
      $or: [
        { username: req.body.username },
        { email: req.body.username }
      ]
    });

    // Check if the user exists and if the provided password matches the stored hashed password
    const isPasswordValid = user && bcrypt.compareSync(req.body.password, user.password);

    if (isPasswordValid) {
      // Log the user in by storing their ID in the session, and send a success response
      req.session.userId = user._id;
      return res.json({ status: 'ok' });
    } 

    // If credentials are incorrect, send a 400 Bad Request response with a custom error message
    res.status(400).json({ errors: [{ msg: 'Invalid username/email or password' }] });
  } catch (err) {
    // Handle unexpected errors by logging them and sending a 500 Internal Server Error response
    console.error('Error occurred during login: ', err);
    res.status(500).json({ errors: [{ msg: 'Error occurred during login' }] });
  }
}
);

// Setting up the '/api/profile' route to handle GET requests
app.get('/api/profile',

// Async request handler for fetching user profile information
async (req, res) => {
  // Ensure user is logged in by checking if there's a userId in the session
  if (!req.session.userId) {
    return res.status(401).json({ error: 'User is not logged in' });
  }

  try {
    // Fetch the user from the 'users' collection using the userId stored in the session
    // Exclude the password from the returned user data for security
    const user = await db.collection('users').findOne(
      { _id: new ObjectId(req.session.userId) },
      { projection: { password: 0 } }
    );

    // If user is not found in the database, send a 404 Not Found response
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Send the retrieved user data as a JSON response
    return res.json(user);
  } catch (err) {
    // Handle any unexpected errors by logging and sending a 500 Internal Server Error response
    console.error('Error occurred during profile retrieval: ', err);
    return res.status(500).json({ error: 'Error occurred during profile retrieval' });
  }
}
);

// Setting up the '/register' route to handle POST requests
app.post('/register', limiter,

// Ensure the 'username' field in the request is populated
body('username').notEmpty().withMessage('Username is required'),

// Ensure the 'password' field in the request is populated
body('password').notEmpty().withMessage('Password is required'),

// Ensure the 'email' field is populated and contains a valid email address
body('email').notEmpty().withMessage('Email is required').isEmail().withMessage('Email is not valid'),

// Validate that the 'passwordConfirmation' field matches the 'password' field
body('passwordConfirmation').custom((value, { req }) => {
  if (value !== req.body.password) {
    throw new Error('Password confirmation does not match password');
  }
  return true;  // Indicates successful validation
}),

// Async request handler for user registration
async (req, res) => {
  // Extract any validation errors from the request
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // If there are validation errors, send a 400 Bad Request with the errors
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    // Securely hash the provided password
    const hashedPassword = bcrypt.hashSync(req.body.password, 10);

    // Check if a user with the provided username or email already exists in the database
    const existingUser = await db.collection('users').findOne({
      $or: [{ username: req.body.username }, { email: req.body.email }]
    });

    if (existingUser) {
      // If such a user exists, send a 400 Bad Request with a custom error message
      return res.status(400).json({ errors: [{ msg: 'Username or email already exists' }] });
    }

    // Insert the new user's details into the database
    const newUser = await db.collection('users').insertOne({
      username: req.body.username,
      password: hashedPassword,
      email: req.body.email
    });

    // Automatically log in the new user by storing their ID in the session
    req.session.userId = newUser.insertedId;
    
    // Send a response indicating successful registration
    return res.json({ status: 'ok' });

  } catch (err) {
    // Handle unexpected errors by logging and sending a 500 Internal Server Error response
    console.error('Error occurred during registration: ', err);
    return res.status(500).json({ errors: [{ msg: 'Error occurred during registration' }] });
  }
}
);

// Setting up the '/api/changeUsername' route to handle POST requests
app.post('/api/changeUsername', limiter,

// Check if the 'newUsername' in the request body is not empty, return a custom error message if it is
body('newUsername').notEmpty().withMessage('New username is required'),

// Declare an async function to handle the request and response
async (req, res) => {
  // Validate the request with the checks defined above
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // If there were validation errors, return a 400 status code (Bad Request) and the array of error objects
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    // Check if a user with the new username already exists
    const existingUser = await db.collection('users').findOne({ username: req.body.newUsername });
    if (existingUser) {
      // If a user was found, return a 400 status code (Bad Request) and a custom error message
      res.status(400).json({ errors: [{ msg: 'Username already exists' }] });
    } else {
      // If no user was found, update the current user's username
      await db.collection('users').updateOne({ _id: new ObjectId(req.session.userId) }, { $set: { username: req.body.newUsername }});

      // Return a response with a status of 'ok'
      res.json({ status: 'ok' });
    }
  } catch (err) {
    // If any errors occurred during this process, log the error and return a 500 status code (Internal Server Error) and a custom error message
    console.error('Error occurred during changing username: ', err);
    res.status(500).json({ errors: [{ msg: 'Error occurred during changing username' }] });
  }
}
);

// Setting up the '/api/changePassword' route to handle POST requests
app.post('/api/changePassword',
ensureAuthenticatedAPI,  // Middleware to ensure user is authenticated

// Check if the 'newPassword' in the request body is not empty, return a custom error message if it is
body('newPassword').notEmpty().withMessage('New password is required'),

// Declare an async function to handle the request and response
async (req, res) => {

  // Validate the request with the checks defined above
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // If there were validation errors, return a 400 status code (Bad Request) and the array of error objects
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    // Fetch the current user from the database
    const currentUser = await db.collection('users').findOne({ _id: new ObjectId(req.session.userId) });

    // Check if the provided old password matches the stored password
    if (!bcrypt.compareSync(req.body.oldPassword, currentUser.password)) {
      return res.status(400).json({ errors: [{ msg: 'Current password is incorrect' }] });
    }

    // Hash the new password
    const hashedPassword = bcrypt.hashSync(req.body.newPassword, 10);

    // Update the current user's password
    await db.collection('users').updateOne({ _id: new ObjectId(req.session.userId) }, { $set: { password: hashedPassword }});

    // Return a response with a status of 'ok'
    res.json({ status: 'ok' });
  } catch (err) {
    // If any errors occurred during this process, log the error and return a 500 status code (Internal Server Error) and a custom error message
    console.error('Error occurred during changing password: ', err);
    res.status(500).json({ errors: [{ msg: 'Error occurred during changing password' }] });
  }
}
);


// Setting up the '/api/changeEmail' route to handle POST requests
app.post('/api/changeEmail', limiter, 

// Check if the 'newEmail' in the request body is not empty and is a valid email, return custom error messages if it isn't
body('newEmail').notEmpty().withMessage('New email is required').isEmail().withMessage('Email is invalid'),

// Declare an async function to handle the request and response
async (req, res) => {
  // Validate the request with the checks defined above
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    // If there were validation errors, return a 400 status code (Bad Request) and the array of error objects
    return res.status(400).json({ errors: errors.array() });
  }

  try {
    // Check if a user with the new email already exists
    const existingUser = await db.collection('users').findOne({ email: req.body.newEmail });
    if (existingUser) {
      // If a user was found, return a 400 status code (Bad Request) and a custom error message
      return res.status(400).json({ errors: [{ msg: 'Email already exists' }] });
    } else {
      // If no user was found, update the current user's email
      await db.collection('users').updateOne({ _id: new ObjectId(req.session.userId) }, { $set: { email: req.body.newEmail }});

      // Return a response with a status of 'ok'
      res.json({ status: 'ok' });
    }
  } catch (err) {
    // If any errors occurred during this process, log the error and return a 500 status code (Internal Server Error) and a custom error message
    console.error('Error occurred during changing email: ', err);
    res.status(500).json({ errors: [{ msg: 'Error occurred during changing email' }] });
  }
}
);

// Setting up the '/api/deleteAccount' route to handle DELETE requests
app.delete('/api/deleteAccount', limiter, 

// Declare an async function to handle the request and response
async (req, res) => {
  try {
    // Delete the current user's document from the 'users' collection in the database
    await db.collection('users').deleteOne({ _id: new ObjectId(req.session.userId) });

    // Destroy the current user's session
    req.session.destroy();

    // Return a response with a status of 'ok'
    res.json({ status: 'ok' });
  } catch (err) {
    // If any errors occurred during this process, log the error and return a 500 status code (Internal Server Error) and a custom error message
    console.error('Error occurred during deleting account: ', err);
    res.status(500).json({ errors: [{ msg: 'Error occurred during deleting account' }] });
  }
}
);

app.get('/logout', (req, res) => {
  if (req.session) {
    req.session.destroy((err) => {
      if (err) {
        console.log(err);
        return res.status(500).json({ success: false, message: 'Error during session destruction' });
      }
      res.json({ success: true });
    });
  } else {
    res.json({ success: true });
  }
});


app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

    










