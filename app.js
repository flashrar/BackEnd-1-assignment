const fs = require('fs');
const express = require('express');
const { Pool } = require('pg');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const flash = require('connect-flash');

const app = express();
const port = 3001;

const pool = new Pool({
  user: 'postgres',
  host: 'localhost',
  database: 'WEB-fullstack',
  password: 'flarar22',
  port: 5432,
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.use(session({
  secret: 'your-secret-key',
  resave: true,
  saveUninitialized: true
}));

app.use(flash());
app.use(passport.initialize());
app.use(passport.session());


passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
    done(null, user.rows[0]);
  } catch (error) {
    console.error(error);
    done(error);
  }
});

passport.use('local-register', new LocalStrategy({
  usernameField: 'username',
  passwordField: 'password',
  passReqToCallback: true
}, async (req, username, password, done) => {
  try {
    // Check if the username is already taken
    const userExists = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    if (userExists.rows.length > 0) {
      return done(null, false, req.flash('registerMessage', 'Username already taken.'));
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user into the database with a default role (e.g., 'user')
    const query = 'INSERT INTO users (username, password, role) VALUES ($1, $2, $3) RETURNING *';
    const values = [username, hashedPassword, 'user'];

    const result = await pool.query(query, values);
    const newUser = result.rows[0];

    return done(null, newUser);
  } catch (error) {
    console.error(error);
    return done(error);
  }
}));


passport.use('local-login', new LocalStrategy({
  usernameField: 'username',
  passwordField: 'password',
  passReqToCallback: true
}, async (req, username, password, done) => {
  try {
    // Check if the user exists in the database
    const user = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

    if (user.rows.length === 0) {
      // User not found
      return done(null, false, req.flash('loginMessage', 'Incorrect username or password.'));
    }

    // Check if the password is correct
    const passwordMatch = await bcrypt.compare(password, user.rows[0].password);

    if (!passwordMatch) {
      // Incorrect password
      return done(null, false, req.flash('loginMessage', 'Incorrect username or password.'));
    }

    // Successful login
    return done(null, user.rows[0]);

  } catch (error) {
    console.error(error);
    return done(error);
  }
}));



const initializeDefaultUsers = async () => {
  try {
    const adminCheckQuery = 'SELECT * FROM users WHERE username = $1';
    const adminCheckValues = ['admin'];
    const adminResult = await pool.query(adminCheckQuery, adminCheckValues);

    if (adminResult.rows.length === 0) {
      const adminPassword = await bcrypt.hash('admin', 10);
      const adminInsertQuery = 'INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4)';
      const adminInsertValues = ['admin', 'admin@example.com', adminPassword, 'admin'];
      await pool.query(adminInsertQuery, adminInsertValues);
    }

    const modCheckQuery = 'SELECT * FROM users WHERE username = $1';
    const modCheckValues = ['mod'];
    const modResult = await pool.query(modCheckQuery, modCheckValues);

    if (modResult.rows.length === 0) {
      const modPassword = await bcrypt.hash('mod', 10);
      const modInsertQuery = 'INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4)';
      const modInsertValues = ['mod', 'mod@example.com', modPassword, 'moderator'];
      await pool.query(modInsertQuery, modInsertValues);
    }

    console.log('Default admin and moderator users created successfully.');
  } catch (error) {
    console.error('Error initializing default users:', error);
  }
};

initializeDefaultUsers();

// routes
// Registration route
app.post('/register', passport.authenticate('local-register', {
  successRedirect: '/dashboard',
  failureRedirect: '/register',
  failureFlash: true,
}));

app.get('/login', (req, res) => {
  res.sendFile(__dirname + '/login.html');
});

// Login route


app.post('/login', (req, res, next) => {
  console.log('Login request:', req.body.username, req.body.password);
  passport.authenticate('local-login', (err, user, info) => {
    if (err) {
      console.error(err);
      return next(err);
    }
    if (!user) {
      console.log('Login failed. Flash messages:', req.flash('loginMessage'));
      return res.redirect('/login');
    }
    req.logIn(user, (err) => {
      if (err) {
        console.error(err);
        return next(err);
      }
      console.log('Successful login, redirecting to /dashboard');
      const role = req.user.role;
      const sitePath = path.join(__dirname, `${role}_usr.html`);
      console.log('Successful login, user role:', role);
      console.log('File path:', sitePath);

      fs.access(sitePath, fs.constants.F_OK, (err) => {
        if (err) {
          console.error(`File not found: ${sitePath}`);
          return res.redirect('https://example.com');
        }
        res.sendFile(sitePath);
      });

    });
  })(req, res, next);
});



const path = require('path');



app.get('/dashboard', isAuthenticated, (req, res) => {
  // Construct the path based on the user's role
  const role = req.user.role;
  const sitePath = path.join(__dirname,  `${role}_usr.html`);
  
  // Check if the file exists
  fs.access(sitePath, fs.constants.F_OK, (err) => {
    if (err) {
      // File doesn't exist, handle the error (e.g., redirect to a default site)
      console.error(`File not found: ${sitePath}`);
      res.redirect('https://example.com'); // Redirect to a default site
    } else {
      // File exists, send the file
      res.sendFile(sitePath);
    }
  });
});


app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});



app.get('/register.html', (req, res) => {
  res.sendFile(__dirname + '/register.html');
});

app.get('/login.html', (req, res) => {
  res.sendFile(__dirname + '/login.html');
});

app.get('/index.html', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});

app.get('/', (req, res) => {
  res.sendFile(__dirname + '/index.html');
});




function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    console.log('Authenticated user:', req.user);
    return next();
  }
  console.log('Not authenticated!');
  res.redirect('/login'); // Redirect to the login page if not authenticated
}



app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
