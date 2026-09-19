# 🧪 Security Test Matrix & Screenshot Capture Guide

This document provides a comprehensive security testing matrix and step-by-step screenshot capture guide for documenting the **Secure Authentication & RBAC System**.

---

## 📊 Automated & Manual Security Testing Matrix

| Test ID | Category | Test Scenario | Test Input / Payload | Expected Outcome | Status |
|---|---|---|---|---|---|
| **TC-01** | Cryptographic Hashing | Verify password hashing in database | `User123!@#` | Raw password is never saved in SQL; saved as `$2b$12$...` Bcrypt hash. | **PASS** |
| **TC-02** | SQL Injection | SQLi in login email field | `' OR '1'='1` | Input rejected with HTTP 400 Validation Error or HTTP 401 Unauthorized. Query structure remains unchanged. | **PASS** |
| **TC-03** | SQL Injection | SQLi comment syntax in email | `admin@example.com' --` | Input rejected; no unauthorized access granted. | **PASS** |
| **TC-04** | Input Validation | Register with weak password | `weak` | Form rejected with validation error: *Password must contain min 8 chars, uppercase, lowercase, digit, special char.* | **PASS** |
| **TC-05** | XSS Sanitization | XSS payload in username field | `<script>alert('xss')</script>` | Script tags rejected by username regex pattern `/^[a-zA-Z0-9_]+$/` and escaped server-side. | **PASS** |
| **TC-06** | Session Security | Unauthenticated dashboard access | `GET /api/user/dashboard` (No cookie) | Server returns HTTP 401 Unauthorized. UI displays Access Denied card. | **PASS** |
| **TC-07** | Session Security | Session cookie flags check | Successful login | Cookie includes `HttpOnly` (JS-inaccessible) and `SameSite=Lax` (CSRF defense). | **PASS** |
| **TC-08** | Session Security | Session Fixation defense | Pre-login vs Post-login session ID | Session ID is regenerated upon successful authentication; old session destroyed. | **PASS** |
| **TC-09** | RBAC Authorization | Regular user accessing admin panel | `GET /api/admin/users` (User session) | Server returns HTTP 403 Forbidden. UI displays RBAC Authorization Blocked card. | **PASS** |
| **TC-10** | RBAC Authorization | Admin accessing admin panel | `GET /api/admin/users` (Admin session) | Server returns HTTP 200 OK with complete array of system users. | **PASS** |
| **TC-11** | RBAC Privilege Edit | Admin demoting/promoting user | `POST /api/admin/change-role` | User role updated in SQL database (`users.role = 'admin'/'user'`) and audit event logged. | **PASS** |
| **TC-12** | Threat Mitigation | Brute-force rate limiting | 6 consecutive failed logins from single IP | 6th request blocked with HTTP 429 Too Many Requests: *Too many authentication attempts. Please try again after 15 minutes.* | **PASS** |

---

## 📸 Step-by-Step Screenshot Capture Guide

When capturing screenshots for your academic project report, course submission, or portfolio presentation, follow these exact steps and capture each visual state listed below:

### 📸 Screenshot 1: System Homepage & Authentication Portal
- **URL:** `http://localhost:3000`
- **Tab:** **Authentication** (`Log In` view)
- **What to Capture:** Header brand (`SecureAuth Lab`), status bar showing `Not Authenticated`, login form with email/password inputs, quick demo account buttons (`Fill Standard User`, `Fill Admin User`), and the right-hand **Built-In Security Features** card.
- **Purpose:** Demonstrates the application landing page and modern dark glassmorphism design system.

### 📸 Screenshot 2: Real-Time Password Strength Meter & Registration Validation
- **URL:** `http://localhost:3000`
- **Tab:** **Authentication** (`Create Account` view)
- **What to Capture:** Type a weak password (e.g., `pass12`) into the registration password field. Capture the visual strength bar (`Weak (Insecure)`), the interactive checklist showing green checkmarks for satisfied rules and red crosses for missing rules (`✖ Min 8 characters`, `✖ Special character`).
- **Purpose:** Highlights client-side validation and password entropy verification.

### 📸 Screenshot 3: Protected User Dashboard & Session Security Inspector
- **URL:** `http://localhost:3000`
- **Tab:** **User Dashboard** (Logged in as `StandardUser` / `user@example.com`)
- **What to Capture:** User Profile card displaying assigned role `USER`, **Live Session Security Inspector** card showing `HttpOnly: TRUE (JS-Inaccessible)` and `SameSite: LAX`, and the **Personal Security Audit Trail** table listing recent user login actions.
- **Purpose:** Demonstrates session security, HTTP cookie flags, and personal audit trail logging.

### 📸 Screenshot 4: Role-Based Access Control (RBAC) 403 Forbidden Block
- **URL:** `http://localhost:3000`
- **Tab:** **Admin Control Panel** (While logged in as standard `user@example.com`)
- **What to Capture:** The RBAC Authorization Block card displaying: `🛡️ RBAC Authorization Blocked (HTTP 403 Forbidden)` and message: *Access Denied: Your active role 'user' does not possess Admin privileges.*
- **Purpose:** Demonstrates server-side authorization enforcement and prevention of Broken Access Control.

### 📸 Screenshot 5: Admin Control Panel & Global Audit Trail
- **URL:** `http://localhost:3000`
- **Tab:** **Admin Control Panel** (Logged in as `SystemAdmin` / `admin@example.com`)
- **What to Capture:** The **User Directory & Privilege Management** table showing registered users with `Promote`/`Demote` role buttons, and the **Global System Security Audit Trail** table showing IP addresses, user IDs, event actions (`LOGIN_SUCCESS`, `UNAUTHORIZED_ACCESS_ATTEMPT`), and timestamps.
- **Purpose:** Illustrates administrative privilege management and security audit logging.

### 📸 Screenshot 6: Anti-Brute-Force Rate Limiting (HTTP 429)
- **URL:** `http://localhost:3000`
- **Action:** Click `Sign In to Account` 6 times repeatedly with invalid credentials.
- **What to Capture:** The error toast notification at the bottom right displaying: `Rate Limited - Too many authentication attempts from this IP. Please try again after 15 minutes.`
- **Purpose:** Proves protection against automated brute-force attacks and credential stuffing.

### 📸 Screenshot 7: Security Learning Center & Interactive Modal
- **URL:** `http://localhost:3000`
- **Tab:** **Security Concepts**
- **What to Capture:** Click on the **SQL Injection (SQLi) Defense** or **Password Salting & Hashing** concept card to open the learning modal. Capture the side-by-side **Vulnerable Code vs. Secure Code** boxes.
- **Purpose:** Showcases the interactive educational learning center component of the project.

### 📸 Screenshot 8: Automated Security Test Runner Terminal Output
- **Terminal Command:** `npm test`
- **What to Capture:** The command terminal showing all 18 automated security test assertions passing cleanly with green tick marks (`18 Passed, 0 Failed`).
- **Purpose:** Provides concrete empirical proof of system security implementation.

---

*Document created for Secure Authentication System & Cybersecurity Learning Project.*
