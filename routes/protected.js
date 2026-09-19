const express = require('express');
const db = require('../config/db');
const { isAuthenticated, hasRole, logAudit } = require('../middleware/auth');

const router = express.Router();

/**
 * @route   GET /api/user/dashboard
 * @desc    Protected Dashboard route accessible by logged-in Users & Admins
 * @access  Private (Authenticated: User or Admin)
 */
router.get('/user/dashboard', isAuthenticated, hasRole('user', 'admin'), (req, res) => {
  const userId = req.session.userId;

  // Retrieve user activity logs
  const logsQuery = `
    SELECT action, status, ip_address, timestamp 
    FROM audit_logs 
    WHERE user_id = ? 
    ORDER BY timestamp DESC 
    LIMIT 10
  `;

  db.all(logsQuery, [userId], (err, logs) => {
    if (err) {
      console.error('Error loading dashboard logs:', err.message);
      return res.status(500).json({ status: 500, error: 'Database Error', message: 'Failed to load user activity history.' });
    }

    return res.status(200).json({
      status: 200,
      message: 'User Dashboard Data Loaded Successfully',
      sessionInfo: {
        sessionID: req.sessionID,
        userId: req.session.userId,
        username: req.session.username,
        role: req.session.role,
        cookieExpires: req.session.cookie.expires,
      },
      recentActivity: logs,
    });
  });
});

/**
 * @route   GET /api/admin/users
 * @desc    Admin Panel: List all registered users in the database
 * @access  Private (Admin Only)
 */
router.get('/admin/users', isAuthenticated, hasRole('admin'), (req, res) => {
  const query = `SELECT id, username, email, role, created_at FROM users ORDER BY id ASC`;

  db.all(query, [], (err, users) => {
    if (err) {
      console.error('Error fetching users:', err.message);
      return res.status(500).json({ status: 500, error: 'Database Error', message: 'Failed to retrieve user list.' });
    }

    logAudit(req, 'ADMIN_VIEWED_USERS_DIRECTORY', 'SUCCESS');

    return res.status(200).json({
      status: 200,
      users,
    });
  });
});

/**
 * @route   GET /api/admin/logs
 * @desc    Admin Panel: List system security audit logs
 * @access  Private (Admin Only)
 */
router.get('/admin/logs', isAuthenticated, hasRole('admin'), (req, res) => {
  const query = `
    SELECT id, user_id, username, action, ip_address, status, timestamp 
    FROM audit_logs 
    ORDER BY id DESC 
    LIMIT 50
  `;

  db.all(query, [], (err, logs) => {
    if (err) {
      console.error('Error fetching audit logs:', err.message);
      return res.status(500).json({ status: 500, error: 'Database Error', message: 'Failed to retrieve system audit logs.' });
    }

    return res.status(200).json({
      status: 200,
      logs,
    });
  });
});

/**
 * @route   POST /api/admin/change-role
 * @desc    Admin Panel: Promote or Demote user role
 * @access  Private (Admin Only)
 */
router.post('/admin/change-role', isAuthenticated, hasRole('admin'), (req, res) => {
  const { targetUserId, newRole } = req.body;

  if (!targetUserId || !['user', 'admin'].includes(newRole)) {
    return res.status(400).json({
      status: 400,
      error: 'Bad Request',
      message: 'Invalid target user ID or role specified.',
    });
  }

  // Parameterized Query to prevent SQL Injection
  const updateQuery = `UPDATE users SET role = ? WHERE id = ?`;

  db.run(updateQuery, [newRole, targetUserId], function (err) {
    if (err) {
      console.error('Error updating role:', err.message);
      return res.status(500).json({ status: 500, error: 'Database Error', message: 'Failed to update user role.' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ status: 404, error: 'Not Found', message: 'Target user not found.' });
    }

    logAudit(req, `ROLE_CHANGED [User ID ${targetUserId} -> ${newRole}]`, 'SUCCESS');

    return res.status(200).json({
      status: 200,
      message: `User role successfully updated to '${newRole}'.`,
    });
  });
});

module.exports = router;
