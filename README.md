# 🔐 Authentify - Scalable Authentication System

A production-oriented authentication system built with a **progressive architecture**, evolving from a basic JWT-based auth API to a **secure, scalable authentication service**.

This project is structured in **three levels**, each representing increasing complexity and real-world applicability.

---

## 🚀 Project Overview

This backend-only project demonstrates how authentication systems evolve in real-world applications:

* 🟢 **Level 1 — Core Authentication API**
* 🟡 **Level 2 — Production-Grade Security**
* 🔴 **Level 3 — Auth as a Service (Advanced Architecture)**

The goal is to not just implement authentication, but to **understand and design secure, scalable systems**.

---
## 🌐 Minimal Frontend (Testing Only)

A lightweight frontend is included to **interact with and test the backend**.

**Tech Used:**
- HTML, CSS, JavaScript  
- Jinja2 (only for serving pages)

**Purpose:**
- Test login, register, and protected routes  
- Simulate real client behavior  
- Validate access + refresh token flow  

**Note:**  
This is **not production-ready** and will be replaced with React later.
---
## 🛠️ Tech Stack

* **Framework:** FastAPI
* **Database:** PostgreSQL
* **Authentication:** JWT (Access + Refresh Tokens)
* **Password Hashing:** Bcrypt
* **Caching / Blacklisting (Level 3):** Redis
* **ORM:** SQLAlchemy

---

# 🟢 Level 1 — Core Authentication API

### 🎯 Objective

Build a clean and functional authentication system with proper token flow.

---

### ✅ Features

* User Registration & Login
* Password Hashing (Bcrypt)
* JWT Authentication

  * Access Token (short-lived)
  * Refresh Token (long-lived)
* Token Refresh Flow
* Logout (Refresh Token Invalidation)
* Protected Routes (`/auth/me`)

---

### 🗄️ Database Schema

#### `users`

* id
* email / username
* hashed_password
* is_active
* created_at

#### `refresh_tokens`

* id
* user_id
* token_hash
* expires_at
* created_at

---

### 📡 API Endpoints

```
POST   /auth/register
POST   /auth/login
POST   /auth/refresh
POST   /auth/logout
GET    /auth/me
```

---

### 🧠 Key Concepts Learned

* JWT lifecycle and token handling
* Dependency injection in FastAPI
* Secure password storage
* Backend route protection

---

# 🟡 Level 2 — Production-Grade Authentication

### 🎯 Objective

Enhance the system with **real-world security features**.

---

### 🔐 Features

#### Account Security

* Email Verification (token-based)
* Forgot Password / Reset Password flow

#### Access Control

* Role-Based Access Control (RBAC)

  * Roles: `user`, `admin`

#### Attack Prevention

* Rate Limiting (e.g., login attempts)
* Account Locking after multiple failures

#### Token Security

* Refresh Token Rotation
* Reuse Detection

---

### 🗄️ Extended Schema

#### `users`

* failed_attempts
* is_verified
* is_locked
* role

#### `password_resets`

* user_id
* token_hash
* expires_at

#### `email_verifications`

* token_hash
* expires_at

---

### 📡 Additional Endpoints

```
POST /auth/verify-email
POST /auth/request-password-reset
POST /auth/reset-password
```

---

### 🧠 Key Concepts Learned

* Secure authentication flows
* Backend-driven security enforcement
* Stateful vs stateless auth decisions
* Handling sensitive workflows safely

---

# 🔴 Level 3 — Auth as a Service

### 🎯 Objective

Design authentication as a **standalone, scalable service**.

---

### 🏗️ Architecture

* Dedicated Auth Service (decoupled from main app)
* Optional API Gateway integration
* Docker-ready service design

---

### 🔥 Features

#### Session Management

* Multi-device session tracking
* Logout from current / all devices

#### Token Management

* Token Blacklisting (Redis)
* Fast revocation checks

#### OAuth Integration

* Google Login (OAuth 2.0)
* Extensible for other providers

#### Observability

* Audit Logs (login, logout, reset, etc.)

#### Service-Level Security

* API Keys for service-to-service communication

---

### 🗄️ Advanced Schema

#### `sessions`

* user_id
* device_info
* ip_address
* last_active
* refresh_token_id

#### `auth_logs`

* user_id
* action
* ip_address
* timestamp

---

### 📡 Advanced Endpoints

```
GET    /sessions
POST   /logout-all
DELETE /sessions/{id}
POST   /oauth/google
```

---

### 🧠 Key Concepts Learned

* System design for authentication
* Distributed authentication strategies
* Session vs token-based systems
* Building reusable backend services

---

# 🧠 Engineering Approach

This project is designed to be built **incrementally**:

1. ✅ Complete Level 1 (fully working system)
2. 🔄 Extend into Level 2 (add security layers)
3. 🏗️ Refactor into Level 3 (service-oriented architecture)

---

# ⚠️ Security Best Practices Implemented

* Passwords are hashed using bcrypt
* Refresh tokens are stored as **hashed values**
* Tokens have proper expiration policies
* Sensitive flows use **time-bound tokens**
* Backend enforces all authentication rules

---

# ❌ Common Pitfalls Avoided

* Storing raw tokens in the database
* Missing token expiration
* Weak password handling
* No logout or session invalidation
* Trusting frontend for authentication

---

# 📌 Future Improvements

* Two-Factor Authentication (2FA)
* Device fingerprinting
* Risk-based authentication
* Rate limiting via distributed systems
* Full API Gateway integration

---

# 📄 License

This project is for educational and demonstration purposes.

---

# 🙌 Final Note

This is not just an authentication system — it’s a **progressive exploration of backend engineering**, security, and system design.

---
