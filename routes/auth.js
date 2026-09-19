const express = require('express');
const bcrypt = require('bcryptjs');
const db = require('../config/db');
const { authLimiter } = require('../middleware/security');
const { registerValidationRules, loginValidationRules, validate } = require('../middleware/validation');
const { isAuthenticated, logAudit } = require('../middleware/auth');

const router = express.Router();

/**
 * @route   POST /api/auth/register
 * @desc    Register a new user account with hashed password
 * @access  Public (Rate-limited)
 */
router.post('/register', authLimiter, registerValidationRules, validate, (req, res) => {
  const { username, email, password } = req.body;

  // Parameterized Query to check if username or email already exists (SQLi Protection)
  const checkQuery = `SELECT * FROM users WHERE email = ? OR username = ?`;

  db.get(checkQuery, [email, username], async (err, existingUser) => {
    if (err) {
      console.error('Database query error:', err.message);
      return res.status(500).json({ status: 500, error: 'Database Error', message: 'Internal database query failure.' });
    }

    if (existingUser) {
      logAudit(req, 'REGISTER_FAILED_DUPLICATE', 'FAILED', null, username);
      return res.status(409).json({
        status: 409,
        error: 'Conflict',
        message: existingUser.email === email ? 'Email address is already registered.' : 'Username is already taken.',
      });
    }

    try {
      // Secure Password Hashing with Bcrypt + Salt Rounds (Cost Factor = 12)
      const saltRounds = 12;
      const passwordHash = await bcrypt.hash(password, saltRounds);

      // Parameterized Query to insert new user safely
      const insertQuery = `INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)`;
      
      db.run(insertQuery, [username, email, passwordHash, 'user'], function (insertErr) {
        if (insertErr) {
          console.error('User creation error:', insertErr.message);
          return res.status(500).json({ status: 500, error: 'Database Error', message: 'Failed to create user account.' });
        }

        const newUserId = this.lastID;

        // Session Regeneration to prevent Session Fixation attacks
        req.session.regenerate((regenErr) => {
          if (regenErr) {
            console.error('Session regeneration error:', regenErr.message);
          }

          req.session.userId = newUserId;
          req.session.username = username;
          req.session.role = 'user';

          logAudit(req, 'USER_REGISTER_SUCCESS', 'SUCCESS', newUserId, username);

          return res.status(201).json({
            status: 201,
            message: 'User registered successfully!',
            user: {
              id: newUserId,
              username,
              email,
              role: 'user',
            },
          });
        });
      });
    } catch (hashErr) {
      console.error('Password hashing error:', hashErr.message);
      return res.status(500).json({ status: 500, error: 'Internal Error', message: 'Error processing password security.' });
    }
  });
});

/**
 * @route   POST /api/auth/login
 * @desc    Authenticate user, generate secure session
 * @access  Public (Rate-limited)
 */
router.post('/login', authLimiter, loginValidationRules, validate, (req, res) => {
  const { email, password } = req.body;

  // Parameterized Query to prevent SQL Injection
  const userQuery = `SELECT * FROM users WHERE email = ?`;

  db.get(userQuery, [email], async (err, user) => {
    if (err) {
      console.error('Database lookup error:', err.message);
      return res.status(500).json({ status: 500, error: 'Database Error', message: 'Internal server error.' });
    }

    if (!user) {
      logAudit(req, `LOGIN_FAILED [Non-existent Email: ${email}]`, 'FAILED');
      return res.status(401).json({
        status: 401,
        error: 'Unauthorized',
        message: 'Invalid email address or password.',
      });
    }

    // Timing-Safe Password Comparison using Bcrypt
    const isPasswordValid = await bcrypt.compare(password, user.password_hash);

    if (!isPasswordValid) {
      logAudit(req, 'LOGIN_FAILED_WRONG_PASSWORD', 'FAILED', user.id, user.username);
      return res.status(401).json({
        status: 401,
        error: 'Unauthorized',
        message: 'Invalid email address or password.',
      });
    }

    // Regenerate Session ID upon successful login (Prevents Session Fixation)
    req.session.regenerate((regenErr) => {
      if (regenErr) {
        console.error('Session regeneration error:', regenErr.message);
        return res.status(500).json({ status: 500, error: 'Session Error', message: 'Could not create secure session.' });
      }

      req.session.userId = user.id;
      req.session.username = user.username;
      req.session.role = user.role;

      logAudit(req, 'LOGIN_SUCCESS', 'SUCCESS', user.id, user.username);

      return res.status(200).json({
        status: 200,
        message: 'Login successful!',
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          role: user.role,
        },
      });
    });
  });
});

/**
 * @route   POST /api/auth/logout
 * @desc    Destroy session and invalidate session cookie
 * @access  Private (Authenticated users)
 */
router.post('/logout', isAuthenticated, (req, res) => {
  const userId = req.session.userId;
  const username = req.session.username;

  logAudit(req, 'LOGOUT_SUCCESS', 'SUCCESS', userId, username);

  req.session.destroy((err) => {
    if (err) {
      console.error('Session destruction error:', err.message);
      return res.status(500).json({ status: 500, error: 'Logout Error', message: 'Could not log out session.' });
    }

    res.clearCookie('connect.sid'); // Clear Express Session Cookie
    return res.status(200).json({
      status: 200,
      message: 'Logged out successfully.',
    });
  });
});

/**
 * @route   GET /api/auth/me
 * @desc    Check current session status and return logged-in user details
 * @access  Public (Returns auth state)
 */
router.get('/me', (req, res) => {
  if (!req.session || !req.session.userId) {
    return res.status(200).json({ authenticated: false, user: null });
  }

  const query = `SELECT id, username, email, role, created_at FROM users WHERE id = ?`;
  db.get(query, [req.session.userId], (err, user) => {
    if (err || !user) {
      return res.status(200).json({ authenticated: false, user: null });
    }

    return res.status(200).json({
      authenticated: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        createdAt: user.created_at,
      },
    });
  });
});

module.exports = router;
