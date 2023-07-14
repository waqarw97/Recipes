require('dotenv').config()
const bcrypt = require('bcrypt');
const express = require('express');
const bodyParser = require('body-parser');
const MongoClient = require('mongodb').MongoClient;

const app = express();
const port = 3000;

//hidden url for database//
const mongodb_url = process.env.MONGODB_URL;

// variable for database
let db;

//connect driver to database//
MongoClient.connect(mongodb_url, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(client => {
    console.log('Connected to Database')
    db = client.db('Recipe-DB') // use your own database name here
    // further code will go here
  })
  .catch(error => console.error('An error occurred connecting to MongoDB: ', error))

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(express.static('.'));

app.post('/register', async (req, res) => {
  // This destructures the body of the request to get the username, email, and password.
  const { username, email, password } = req.body;
  // This determines the strength of the password hashing.
  const saltRounds = 10;  
  // This hashes the password asynchronously.
  const hashedPassword = await bcrypt.hash(password, saltRounds);
  // This creates a user object.
  const user = { username, email, password: hashedPassword };

  try {
    // Attempt to insert the user into the database
    await db.collection('users').insertOne(user);
    
    // If the operation was successful, log it and redirect the user
    console.log('User registered successfully: ', user);
    res.redirect('/success.html');
  } catch (err) {
    // If an error occurred, log it and send an error response
    console.error('Error occurred during registration: ', err);
    res.status(500).send('An error occurred during registration.');
  }
});


app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Try to find the user in the database, the $or helps find the user based on username or email
  const user = await db.collection('users').findOne({ $or: [{ username }, { email: username }] });

  if (!user) {
      console.error('User not found during login: ', username);
      res.status(401).send('Invalid username or password.');
      return;
  }

  // Check the provided password against the stored hash
  const passwordCorrect = await bcrypt.compare(password, user.password);
  if (!passwordCorrect) {
      console.error('Incorrect password during login for: ', username);
      res.status(401).send('Invalid username or password.');
      return;
  }

  console.log('User logged in successfully: ', username);
  res.redirect('/success.html');
});



app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});





