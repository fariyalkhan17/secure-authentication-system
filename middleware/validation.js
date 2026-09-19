const { body, validationResult } = require('express-validator');

// Validation & Sanitization Rules for User Registration
const registerValidationRules = [
  body('username')
    .trim()
    .notEmpty().withMessage('Username is required.')
    .isLength({ min: 3, max: 30 }).withMessage('Username must be between 3 and 30 characters.')
    .matches(/^[a-zA-Z0-9_]+$/).withMessage('Username can only contain letters, numbers, and underscores.')
    .escape(), // Defense against XSS Injection

  body('email')
    .trim()
    .notEmpty().withMessage('Email is required.')
    .isEmail().withMessage('Please provide a valid email address.')
    .normalizeEmail(),

  body('password')
    .notEmpty().withMessage('Password is required.')
    .isLength({ min: 8 }).withMessage('Password must be at least 8 characters long.')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character (@$!%*?&).'),
];

// Validation Rules for User Login
const loginValidationRules = [
  body('email')
    .trim()
    .notEmpty().withMessage('Email is required.')
    .isEmail().withMessage('Please enter a valid email address.')
    .normalizeEmail(),

  body('password')
    .notEmpty().withMessage('Password is required.'),
];

// Validation Result Handler Middleware
function validate(req, res, next) {
  const errors = validationResult(req);
  if (errors.isEmpty()) {
    return next();
  }

  const extractedErrors = errors.array().map((err) => ({
    field: err.path || err.param,
    message: err.msg,
  }));

  return res.status(400).json({
    status: 400,
    error: 'Validation Error',
    message: 'Input validation failed.',
    errors: extractedErrors,
  });
}

module.exports = {
  registerValidationRules,
  loginValidationRules,
  validate,
};
