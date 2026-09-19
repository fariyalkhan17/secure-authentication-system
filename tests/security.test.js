/**
 * Automated Security & Authentication Test Suite
 * Tests Password Hashing, SQL Injection, XSS Sanitization, Session Security, RBAC, and Rate Limiting
 */

const http = require('http');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcryptjs');

process.env.NODE_ENV = 'test';

// Import Express app without starting listener
const app = require('../server');

let server;
const PORT = 3001; // Use port 3001 for test runner
const BASE_URL = `http://localhost:${PORT}`;

function makeRequest(method, path, body = null, headers = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(path, BASE_URL);
    const options = {
      method,
      hostname: url.hostname,
      port: url.port,
      path: url.pathname + url.search,
      headers: {
        'Content-Type': 'application/json',
        ...headers,
      },
    };

    const req = http.request(options, (res) => {
      let data = '';
      const cookies = res.headers['set-cookie'] || [];

      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = data ? JSON.parse(data) : {};
          resolve({ status: res.statusCode, headers: res.headers, cookies, data: json });
        } catch (e) {
          resolve({ status: res.statusCode, headers: res.headers, cookies, raw: data });
        }
      });
    });

    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function runTests() {
  console.log('\n=======================================================');
  console.log('🧪 RUNNING AUTOMATED SECURITY & AUTHENTICATION TEST SUITE');
  console.log('=======================================================\n');

  let passed = 0;
  let failed = 0;

  function assert(condition, testName, failureDetail = '') {
    if (condition) {
      console.log(`  ✅ PASS: ${testName}`);
      passed++;
    } else {
      console.log(`  ❌ FAIL: ${testName} ${failureDetail ? '(' + failureDetail + ')' : ''}`);
      failed++;
    }
  }

  // Start HTTP Server
  server = app.listen(PORT);
  await new Promise(r => setTimeout(r, 1000));

  try {
    // -----------------------------------------------------------------
    // TEST GROUP 1: Database Storage & Password Hashing Verification
    // -----------------------------------------------------------------
    console.log('📌 Test Group 1: Cryptographic Password Storage');
    const dbPath = path.resolve(__dirname, '../database.sqlite');
    const db = new sqlite3.Database(dbPath);

    let dbUser;
    for (let attempts = 0; attempts < 10; attempts++) {
      dbUser = await new Promise((res) => {
        db.get("SELECT * FROM users WHERE email = 'user@example.com'", [], (err, row) => res(row));
      });
      if (dbUser) break;
      await new Promise(r => setTimeout(r, 200));
    }

    assert(dbUser !== undefined, 'Default test user exists in SQLite database');
    if (dbUser) {
      assert(dbUser.password_hash.startsWith('$2a$') || dbUser.password_hash.startsWith('$2b$'), 
        'Password in SQLite is stored as valid Bcrypt Hash (starts with $2a$/$2b$)', `Actual: ${dbUser.password_hash}`);
      assert(dbUser.password_hash !== 'User123!@#', 'Plaintext password is NEVER stored in database');

      const isMatch = await bcrypt.compare('User123!@#', dbUser.password_hash);
      assert(isMatch === true, 'Bcrypt compare matches raw password against stored hash');
    }

    db.close();

    // -----------------------------------------------------------------
    // TEST GROUP 2: SQL Injection (SQLi) Defense Tests
    // -----------------------------------------------------------------
    console.log('\n📌 Test Group 2: SQL Injection (SQLi) Defense');

    const sqliLogin1 = await makeRequest('POST', '/api/auth/login', {
      email: "' OR '1'='1",
      password: "password123",
    }, { 'X-Forwarded-For': '10.0.0.2' });
    assert(sqliLogin1.status === 400 || sqliLogin1.status === 401, 'SQLi Payload ("\' OR \'1\'=\'1") in email is safely blocked');

    const sqliLogin2 = await makeRequest('POST', '/api/auth/login', {
      email: "admin@example.com' --",
      password: "wrongpassword",
    }, { 'X-Forwarded-For': '10.0.0.2' });
    assert(sqliLogin2.status === 400 || sqliLogin2.status === 401, 'SQLi Comment Payload ("admin@example.com\' --") fails authentication');

    // -----------------------------------------------------------------
    // TEST GROUP 3: Input Validation & Sanitization Tests
    // -----------------------------------------------------------------
    console.log('\n📌 Test Group 3: Input Validation & Sanitization');

    const invalidReg1 = await makeRequest('POST', '/api/auth/register', {
      username: 'usr',
      email: 'not-an-email',
      password: 'weak',
    }, { 'X-Forwarded-For': '10.0.0.3' });
    assert(invalidReg1.status === 400, 'Weak password & invalid email rejected with HTTP 400 Validation Error');

    const xssReg = await makeRequest('POST', '/api/auth/register', {
      username: "<script>alert('xss')</script>",
      email: "xss_test@example.com",
      password: "SecurePassword123!@#",
    }, { 'X-Forwarded-For': '10.0.0.3' });
    assert(xssReg.status === 400, 'XSS Script tags in username fail character whitelist validation');

    // -----------------------------------------------------------------
    // TEST GROUP 4: Authentication & Session Security Tests
    // -----------------------------------------------------------------
    console.log('\n📌 Test Group 4: Authentication & Session Security');

    const unauthDashboard = await makeRequest('GET', '/api/user/dashboard');
    assert(unauthDashboard.status === 401, 'Unauthenticated request to /api/user/dashboard yields HTTP 401 Unauthorized');

    // Perform valid User Login
    const userLoginRes = await makeRequest('POST', '/api/auth/login', {
      email: 'user@example.com',
      password: 'User123!@#',
    }, { 'X-Forwarded-For': '10.0.0.4' });
    assert(userLoginRes.status === 200, 'Valid user login returns HTTP 200 OK');
    
    const sessionCookie = userLoginRes.cookies[0];
    assert(sessionCookie && sessionCookie.includes('HttpOnly'), 'Session cookie includes HttpOnly security flag');
    assert(sessionCookie && sessionCookie.includes('SameSite=Lax'), 'Session cookie includes SameSite=Lax flag');

    // Extract cookie string for subsequent authenticated requests
    const cookieHeader = sessionCookie.split(';')[0];

    const authDashboard = await makeRequest('GET', '/api/user/dashboard', null, { Cookie: cookieHeader });
    assert(authDashboard.status === 200, 'Authenticated request with session cookie succeeds (HTTP 200 OK)');

    // -----------------------------------------------------------------
    // TEST GROUP 5: Role-Based Access Control (RBAC) Enforcement
    // -----------------------------------------------------------------
    console.log('\n📌 Test Group 5: Role-Based Access Control (RBAC)');

    const userAccessAdmin = await makeRequest('GET', '/api/admin/users', null, { Cookie: cookieHeader });
    assert(userAccessAdmin.status === 403, 'Standard user accessing /api/admin/users receives HTTP 403 Forbidden');

    // Perform Admin Login
    const adminLoginRes = await makeRequest('POST', '/api/auth/login', {
      email: 'admin@example.com',
      password: 'Admin123!@#',
    }, { 'X-Forwarded-For': '10.0.0.5' });
    assert(adminLoginRes.status === 200, 'Valid Admin login succeeds', `Status: ${adminLoginRes.status}, Message: ${JSON.stringify(adminLoginRes.data)}`);
    
    const adminCookieHeader = adminLoginRes.cookies && adminLoginRes.cookies[0] ? adminLoginRes.cookies[0].split(';')[0] : '';

    const adminAccessAdmin = await makeRequest('GET', '/api/admin/users', null, { Cookie: adminCookieHeader });
    assert(adminAccessAdmin.status === 200, 'Admin user accessing /api/admin/users succeeds (HTTP 200 OK)');
    assert(Array.isArray(adminAccessAdmin.data.users), 'Admin endpoint returns array of registered users');

    // -----------------------------------------------------------------
    // TEST GROUP 6: Rate Limiting & Anti-Brute-Force Protection
    // -----------------------------------------------------------------
    console.log('\n📌 Test Group 6: Rate Limiting & Anti-Brute-Force');

    let rateLimitTriggered = false;
    for (let i = 0; i < 7; i++) {
      const res = await makeRequest('POST', '/api/auth/login', {
        email: `brute_${i}@example.com`,
        password: 'WrongPassword123!',
      }, { 'X-Forwarded-For': '10.0.0.6' }); // Unique IP for rate limit test

      if (res.status === 429) {
        rateLimitTriggered = true;
        break;
      }
    }
    assert(rateLimitTriggered === true, 'Excessive auth attempts (>5) trigger HTTP 429 Rate Limit block');

  } catch (err) {
    console.error('Test execution error:', err);
  } finally {
    server.close();
    console.log('\n=======================================================');
    console.log(`📊 TEST RESULTS: ${passed} Passed, ${failed} Failed`);
    console.log('=======================================================\n');
    process.exit(failed > 0 ? 1 : 0);
  }
}

runTests();
