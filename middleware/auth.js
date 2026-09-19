const db = require('../config/db');

/**
 * Middleware: Verify that user is authenticated with an active session
 */
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    return next();
  }
  return res.status(401).json({
    status: 401,
    error: 'Unauthorized',
    message: 'Access Denied: You must be logged in to access this resource.',
  });
}

/**
 * Middleware: Role-Based Access Control (RBAC) Authorization Check
 * @param {...string} allowedRoles Allowed user roles (e.g. 'admin', 'user')
 */
function hasRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.session || !req.session.role) {
      return res.status(401).json({
        status: 401,
        error: 'Unauthorized',
        message: 'Access Denied: Active session required.',
      });
    }

    if (!allowedRoles.includes(req.session.role)) {
      // Log unauthorized attempt in audit log
      logAudit(req, `UNAUTHORIZED_ACCESS_ATTEMPT [${req.originalUrl}]`, 'BLOCKED', req.session.userId, req.session.username);

      return res.status(403).json({
        status: 403,
        error: 'Forbidden',
        message: `Access Denied: Requires [${allowedRoles.join(', ')}] role privilege.`,
      });
    }

    next();
  };
}

/**
 * Utility: Log security audit events to SQL database
 */
function logAudit(req, action, status, userId = null, username = null) {
  const ipAddress = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  const effectiveUserId = userId || (req.session ? req.session.userId : null);
  const effectiveUsername = username || (req.session ? req.session.username : 'Anonymous');

  const query = `
    INSERT INTO audit_logs (user_id, username, action, ip_address, status)
    VALUES (?, ?, ?, ?, ?)
  `;

  db.run(query, [effectiveUserId, effectiveUsername, action, ipAddress, status], (err) => {
    if (err) {
      console.error('⚠️ Failed to write audit log:', err.message);
    }
  });
}

module.exports = {
  isAuthenticated,
  hasRole,
  logAudit,
};
