const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

const dbPath = path.resolve(__dirname, '../database.sqlite');
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('❌ Failed to connect to SQLite database:', err.message);
  } else {
    console.log('✅ Connected to SQLite database at:', dbPath);
  }
});

// Initialize Tables and Seed Initial Data
db.serialize(() => {
  // 1. Create Users Table
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL DEFAULT 'user',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 2. Create Security Audit Logs Table
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT,
      action TEXT NOT NULL,
      ip_address TEXT,
      status TEXT NOT NULL,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // 3. Seed Default Accounts if Not Exists
  const saltRounds = 12;
  const userPasswordHash = bcrypt.hashSync('User123!@#', saltRounds);
  const adminPasswordHash = bcrypt.hashSync('Admin123!@#', saltRounds);

  const stmt = db.prepare(`
    INSERT OR IGNORE INTO users (username, email, password_hash, role)
    VALUES (?, ?, ?, ?)
  `);

  stmt.run('StandardUser', 'user@example.com', userPasswordHash, 'user');
  stmt.run('SystemAdmin', 'admin@example.com', adminPasswordHash, 'admin');
  stmt.finalize();

  console.log('✅ Demo accounts ready:');
  console.log('   - Regular User: user@example.com | Pass: User123!@#');
  console.log('   - Admin User:   admin@example.com | Pass: Admin123!@#');
});

module.exports = db;
