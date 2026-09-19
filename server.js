const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const path = require('path');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config();

const db = require('./config/db');
const { helmetMiddleware, apiLimiter } = require('./middleware/security');
const authRoutes = require('./routes/auth');
const protectedRoutes = require('./routes/protected');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust reverse proxy header (X-Forwarded-For) for rate limiting & IP tracking
app.set('trust proxy', 1);

// 1. Helmet Security Headers
app.use(helmetMiddleware);

// 2. CORS Configuration
app.use(
  cors({
    origin: `http://localhost:${PORT}`,
    credentials: true,
  })
);

// 3. Request Body Parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 4. Session Security Management (HttpOnly & SameSite cookies)
app.use(
  session({
    store: new SQLiteStore({
      db: 'database.sqlite',
      dir: __dirname,
      table: 'sessions',
    }),
    secret: process.env.SESSION_SECRET || 'super_secret_cybersecurity_learning_key_2026',
    resave: false,
    saveUninitialized: false, // Prevents creating empty sessions for unauthenticated users
    name: 'connect.sid', // Default express session cookie name
    cookie: {
      httpOnly: true, // Prevents client-side JS (document.cookie) from accessing session cookie (XSS defense)
      secure: false, // Set to true in production with HTTPS
      sameSite: 'lax', // CSRF protection
      maxAge: 24 * 60 * 60 * 1000, // 24 Hours
    },
  })
);

// 5. Apply Global API Rate Limiter
app.use('/api/', apiLimiter);

// 6. Serve Static Frontend Files
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

// 7. API Routes
app.use('/api/auth', authRoutes);
app.use('/api', protectedRoutes);

// 8. Serve Frontend Application SPA Entry (Express 5 wildcard fallback)
app.use((req, res, next) => {
  if (req.method === 'GET' && !req.path.startsWith('/api')) {
    return res.sendFile(path.join(__dirname, 'public', 'index.html'));
  }
  next();
});

// 9. Global Error Handler Middleware
app.use((err, req, res, next) => {
  console.error('Unhandled Application Error:', err.stack);
  res.status(500).json({
    status: 500,
    error: 'Internal Server Error',
    message: 'An unexpected security or application error occurred.',
  });
});

// Start Server
app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`🚀 Secure Authentication System Running!`);
  console.log(`🌐 URL: http://localhost:${PORT}`);
  console.log(`🔐 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`=======================================================`);
});

module.exports = app;
