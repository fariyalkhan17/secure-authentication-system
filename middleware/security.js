const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

// Security Headers setup via Helmet
const helmetMiddleware = helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"], // Allow self and inline scripts for learning UI components
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      upgradeInsecureRequests: [],
    },
  },
  crossOriginEmbedderPolicy: false,
});

// Strict Rate Limiter for Authentication endpoints (Login / Register)
// Limits to 5 attempts per 15 minutes per IP to prevent Brute-Force & Credential Stuffing
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Limit each IP to 5 requests per windowMs
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false, // Disable `X-RateLimit-*` headers
  message: {
    status: 429,
    error: 'Too Many Requests',
    message: 'Too many authentication attempts from this IP. Please try again after 15 minutes.',
  },
});

// General Rate Limiter for all API routes (100 requests per 15 minutes)
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 429,
    error: 'Too Many Requests',
    message: 'Rate limit exceeded. Please slow down your requests.',
  },
});

module.exports = {
  helmetMiddleware,
  authLimiter,
  apiLimiter,
};
