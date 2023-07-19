// Importing the necessary dependencies
require('dotenv').config() // Enables environment variables from .env file
const bcrypt = require('bcrypt'); // For hashing passwords
const express = require('express'); // Web server
const bodyParser = require('body-parser'); // For parsing the body of requests
const MongoClient = require('mongodb').MongoClient; // Database driver
const session = require('express-session');  // For handling user sessions

// Create an instance of an express server
const app = express();
const port = 3000; // Port where our server will be listening

// Configure Express to parse request bodies and serve static files
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('.'));

// Use express-session for session management
app.use(session({
  secret: process.env.SESSION_SECRET,  // Use secret from environment variables
  resave: false,
  saveUninitialized: false,
}));

// Get MongoDB URL from environment variables
const mongodb_url = process.env.MONGODB_URL;

// Variable to hold the database connection
let db;

// Connect to the MongoDB server
MongoClient.connect(mongodb_url, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(client => {
    console.log('Connected to Database')
    // Connect to the specific database
    db = client.db('Recipe-DB') // use your own database name here
  })
  .catch(error => console.error('An error occurred connecting to MongoDB: ', error))

// Endpoint for registration
app.post('/register', async (req, res) => {
  // Extract username, email, and password from the request body
  const { username, email, password } = req.body;

  // Check if user with same username or email already exists
  const existingUser = await db.collection('users').findOne({ $or: [{ username }, { email }] });

  // If a user is found, respond with an error message
  if (existingUser) {
    return res.status(400).send('Username or email already exists');
  }

  // Hash the password
  const saltRounds = 10;
  const hashedPassword = await bcrypt.hash(password, saltRounds);

  // Create user object
  const user = { username, email, password: hashedPassword };

  try {
    // Insert the user into the database
    await db.collection('users').insertOne(user);

    // Respond with a success message
    res.status(200).send('User registered successfully');
  } catch (err) {
    // If an error occurred, log it and respond with an error message
    console.error('Error occurred during registration: ', err);
    res.status(500).send('An error occurred during registration.');
  }
});

// Endpoint for login
app.post('/login', async (req, res) => {
  // Extract username and password from the request body
  const { username, password } = req.body;

  try {
    // Check if a user with the provided username or email exists
    const user = await db.collection('users').findOne({ $or: [{ username }, { email: username }] });

    if (user) {
      // Check if the provided password matches the hashed password in the database
      const passwordMatch = await bcrypt.compare(password, user.password);

      if (passwordMatch) {
        // Store the user's ID in the session
        req.session.userId = user._id;
        // Send success response
        res.status(200).send('Login successful');
      } else {
        // If the passwords don't match, send an error response
        res.status(401).send('Invalid credentials');
      }
    } else {
      // If no user was found, send an error response
      res.status(404).send('User not found');
    }
  } catch (err) {
    // If an error occurred, log it and send an error response
    console.error('Error occurred during login: ', err);
    res.status(500).send('An error occurred during login.');
  }
});

// Basic endpoint for testing
app.get('/', (req, res) => {
  res.send('Hello World!');
});

// Start the server and listen on the defined port
app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});






