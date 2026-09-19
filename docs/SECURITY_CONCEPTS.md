# 🛡️ Cybersecurity Learning Guide: Core Web Security Concepts

Welcome to the **Secure Authentication & Role-Based Access Control (RBAC) Learning Guide**. This document explains each security mechanism implemented in this project using beginner-friendly language, real-world analogies, vulnerability comparisons, and code snippets.

---

## Table of Contents
1. [Password Hashing & Salting (Bcrypt)](#1-password-hashing--salting-bcrypt)
2. [SQL Injection (SQLi) Defense via Parameterized Queries](#2-sql-injection-sqli-defense-via-parameterized-queries)
3. [Cross-Site Scripting (XSS) & Input Sanitization](#3-cross-site-scripting-xss--input-sanitization)
4. [Session Fixation & Cookie Security Flags](#4-session-fixation--cookie-security-flags)
5. [Role-Based Access Control (RBAC)](#5-role-based-access-control-rbac)
6. [Rate Limiting & Anti-Brute-Force Protection](#6-rate-limiting--anti-brute-force-protection)

---

## 1. Password Hashing & Salting (Bcrypt)

### 💡 Beginner-Friendly Explanation
Imagine a user sets their password to `Password123!`. If a web server saves `Password123!` in a database as plain text, anyone who accesses the database (such as a dishonest employee or an attacker exploiting a database leak) immediately gains access to every user's account.

- **Plaintext Storage (Catastrophic):** Saving raw passwords directly.
- **Fast Hashing (Insecure):** Using functions like `MD5` or `SHA-256`. Attackers use GPU clusters capable of testing **billions of hashes per second** or pre-computed lookup tables called **Rainbow Tables**.
- **Cryptographic Salting (Secure):** A unique, random string (the "salt") is generated for *every single password* before hashing. Even if two users choose `Password123!`, their stored hashes will look completely different.
- **Bcrypt Work Factor (Cost Factor):** Bcrypt uses an adaptive algorithm that intentionally consumes CPU time. In our system, `saltRounds = 12` forces the server to compute 2<sup>12</sup> (4,096) rounds per password check, making brute-force cracking mathematically infeasible.

### ⚠️ Vulnerable vs. ✅ Secure Implementation

#### ❌ Vulnerable Implementation (Plaintext or Fast Hash)
```javascript
// DANGEROUS: Storing raw user passwords in database
db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, password]);
```

#### ✅ Secure Implementation (`bcryptjs` in Node.js)
```javascript
const bcrypt = require('bcryptjs');
const saltRounds = 12;

// Hash raw password with random salt before saving to SQL
const passwordHash = await bcrypt.hash(password, saltRounds);
db.run("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", 
  [username, email, passwordHash]);
```

---

## 2. SQL Injection (SQLi) Defense via Parameterized Queries

### 💡 Beginner-Friendly Explanation
SQL (Structured Query Language) is the language used to communicate with databases. **SQL Injection** happens when user input is mixed directly with SQL commands. 

An attacker can type a special string into a login field, such as:
`admin@example.com' OR '1'='1`

If the application concatenates input directly into the query:
```sql
SELECT * FROM users WHERE email = 'admin@example.com' OR '1'='1' AND password = '...';
```
Because `'1'='1'` is always true, the database returns the admin user row without verifying the password!

### 🛡️ How Parameterized Queries (Prepared Statements) Stop SQLi
Prepared statements separate the **SQL code structure** from the **user data**:
1. The server sends the SQL template (`SELECT * FROM users WHERE email = ?`) to the database compiler first.
2. The user input (`admin@example.com' OR '1'='1`) is sent separately as a literal string parameter.
3. The database treats the input strictly as data text, never as executable code commands.

### ⚠️ Vulnerable vs. ✅ Secure Implementation

#### ❌ Vulnerable Implementation (String Concatenation)
```javascript
// DANGEROUS: Concatenating input directly into query string
const query = "SELECT * FROM users WHERE email = '" + req.body.email + "'";
db.get(query, (err, user) => { ... });
```

#### ✅ Secure Implementation (SQLite3 Parameterized Statement)
```javascript
// SECURE: Placeholders (?) bind input as literal parameters
const query = "SELECT * FROM users WHERE email = ?";
db.get(query, [req.body.email], (err, user) => { ... });
```

---

## 3. Cross-Site Scripting (XSS) & Input Sanitization

### 💡 Beginner-Friendly Explanation
**Cross-Site Scripting (XSS)** occurs when an attacker inserts JavaScript code (like `<script>alert('hack')</script>`) into a web page field. When another user views that page, their browser executes the script automatically. This script could read secret cookies, log keystrokes, or redirect the user to a phishing website.

### 🛡️ Defenses Implemented in This System
1. **Server-Side Input Sanitization (`express-validator`):** Converts special characters like `<` and `>` into safe HTML entities (`&lt;` and `&gt;`).
2. **Content Security Policy (CSP - Helmet):** HTTP header instructing browsers to execute scripts only from trusted sources (`'self'`).
3. **Safe DOM Text Rendering:** Using `.textContent` or escaping HTML strings instead of raw `.innerHTML`.

### ⚠️ Vulnerable vs. ✅ Secure Implementation

#### ❌ Vulnerable Implementation (Raw DOM Injection)
```javascript
// DANGEROUS: Directly rendering unescaped user string into DOM
document.getElementById('username-display').innerHTML = "Hello " + user.username;
```

#### ✅ Secure Implementation (Server Sanitization + Client Escaping)
```javascript
// Server-side express-validator rule
body('username').trim().escape();

// Client-side escaping helper
function escapeHTML(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
element.innerHTML = "Hello " + escapeHTML(user.username);
```

---

## 4. Session Fixation & Cookie Security Flags

### 💡 Beginner-Friendly Explanation
When you log into a web app, the server creates a **Session** and sends back a unique Session ID in a cookie (e.g., `connect.sid`). For every future request, your browser sends this cookie to prove who you are.

- **Session Fixation Threat:** An attacker tricks a victim into using a known Session ID (e.g., via a malicious URL parameter). If the server doesn't issue a new Session ID after login, the attacker uses that same ID to access the victim's account.
- **Session Hijacking (XSS Cookie Theft):** If an attacker injects JavaScript via XSS, they can run `document.cookie` to steal the Session ID.

### 🛡️ Defenses Implemented
1. **`HttpOnly` Flag:** Prevents client-side JavaScript (`document.cookie`) from accessing the session cookie.
2. **`SameSite=Lax` Flag:** Protects against Cross-Site Request Forgery (CSRF) by preventing the cookie from being sent on cross-site requests.
3. **Session Regeneration (`req.session.regenerate()`):** Immediately destroys the old pre-login Session ID and generates a new random key upon successful login.

### ✅ Secure Session Configuration (`express-session`)
```javascript
app.use(session({
  store: new SQLiteStore({ db: 'database.sqlite' }),
  secret: 'super_secret_cybersecurity_learning_key_2026',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,  // Blocks JavaScript document.cookie access
    sameSite: 'lax',  // Prevents CSRF attacks
    maxAge: 24 * 60 * 60 * 1000 // 24 Hours
  }
}));

// Regenerate Session ID on successful login
req.session.regenerate(() => {
  req.session.userId = user.id;
  req.session.role = user.role;
});
```

---

## 5. Role-Based Access Control (RBAC)

### 💡 Beginner-Friendly Explanation
**Role-Based Access Control (RBAC)** assigns permissions based on user roles (e.g., `user` vs. `admin`).

- **OWASP #1 Threat: Broken Access Control:** Hiding an "Admin Panel" button in the frontend navigation is NOT security. An attacker can open browser developer tools or Postman and send a direct request to `/api/admin/users`.
- **Principle of Least Privilege:** Users should only have access to the absolute minimum data required for their task. Every administrative API route must enforce server-side role validation middleware.

### ✅ Secure RBAC Middleware Implementation
```javascript
function hasRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.session || !allowedRoles.includes(req.session.role)) {
      return res.status(403).json({
        status: 403,
        error: 'Forbidden',
        message: `Access Denied: Requires [${allowedRoles.join(', ')}] role privilege.`
      });
    }
    next();
  };
}

// Protected Route Configuration
router.get('/admin/users', isAuthenticated, hasRole('admin'), (req, res) => {
  // Only executed if user possesses 'admin' role
});
```

---

## 6. Rate Limiting & Anti-Brute-Force Protection

### 💡 Beginner-Friendly Explanation
Automated bots perform **Brute-Force** or **Credential Stuffing** attacks by making thousands of login requests per minute trying common passwords.

**Rate Limiting** tracks the number of requests originating from an IP address within a specific time window. If an IP exceeds 5 failed login attempts in 15 minutes, the server temporarily blocks the IP and responds with HTTP `429 Too Many Requests`.

### ✅ Secure Rate Limiting Configuration (`express-rate-limit`)
```javascript
const rateLimit = require('express-rate-limit');

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 Minute Window
  max: 5, // Maximum 5 authentication requests per IP
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    status: 429,
    error: 'Too Many Requests',
    message: 'Too many authentication attempts. Please try again after 15 minutes.'
  }
});

router.post('/api/auth/login', authLimiter, (req, res) => { ... });
```

---

*Document created for Secure Authentication System & Cybersecurity Learning Project.*
