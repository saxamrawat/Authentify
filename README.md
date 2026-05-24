# 🔐 Authentify - Scalable Authentication System

A production-oriented authentication system built with a **progressive architecture**, evolving from a basic JWT-based auth API to a **secure, scalable authentication platform**.

This project is structured in **three levels**, each representing increasing complexity and real-world applicability.

---

# 🚀 Project Overview

This project demonstrates how authentication systems evolve in real-world applications:

- 🟢 Level 1 — Core Authentication System
- 🟡 Level 2 — Production-Grade Authentication & Security
- 🔴 Level 3 — Auth Platform / Authentication as a Service

The goal is not just to implement authentication, but to **understand and design secure, scalable backend systems**.

---

# 🌐 Minimal Frontend (Testing Only)

A lightweight frontend is included to interact with and test the backend authentication flows.

## Tech Used
- HTML
- CSS
- JavaScript
- Jinja2 (only for serving pages)

## Purpose
- Test login/register flows
- Simulate real client behavior
- Validate access + refresh token flow
- Test protected routes

> This frontend is intentionally minimal and will later be replaced with React.

---

# 🛠️ Tech Stack

- **Framework:** FastAPI
- **Database:** PostgreSQL / SQLite (Development)
- **ORM:** SQLAlchemy
- **Authentication:** JWT (Access + Refresh Tokens)
- **Password Hashing:** Bcrypt
- **Future Caching / Blacklisting:** Redis
- **Templating:** Jinja2

---

# 🟢 Level 1 — Core Authentication System (Overwritten)

## 🎯 Objective

Build a secure JWT-based authentication system with proper session handling fundamentals.

---

## ✅ Features

- User Registration & Login
- Password Hashing with Bcrypt
- JWT Authentication
  - Access Tokens
  - Refresh Tokens
- Token Refresh Flow
- Logout Endpoint
- Protected Routes (`/auth/me`)
- Session Tracking using Refresh Tokens
- Minimal Frontend for Backend Testing

---

## 🗄️ Database Schema

### `users`

- id
- email
- username
- hashed_password

### `refresh_tokens`

- id
- user_id
- hashed_token
- expires_at
- is_revoked

---

## 📡 API Endpoints

```bash
POST   /auth/register
POST   /auth/login
POST   /auth/refresh
POST   /auth/logout
GET    /auth/me
```

---

## 🧠 Key Concepts Learned

- JWT lifecycle management
- Access vs Refresh Token architecture
- Secure password storage
- FastAPI dependency injection
- Protected route handling
- Basic session invalidation
- Frontend-backend authentication interaction

---

# 🟡 Level 2 — Production-Grade Authentication & Security (Currently Deployed)

## 🎯 Objective

Extend the core authentication system with real-world security architecture and attack prevention mechanisms.

---

## 🔐 Features

### Account Security

- Email Verification Flow
- Forgot Password / Reset Password
- Time-Bound Security Tokens

---

### Access Control

- Role-Based Access Control (RBAC)
  - `user`
  - `admin`

### Admin APIs

- Lock User
- Unlock User
- Change User Roles

---

### Attack Prevention

- IP-Based Rate Limiting
- Account Locking after Failed Attempts
- Session Revocation on Suspicious Activity

---

### Token Security

- Refresh Token Rotation
- Refresh Token Reuse Detection
- Global Session Revocation
- Logout with Token Revocation

---

### Validation & Data Integrity

- Password Strength Validation
- Username Validation
- Email Validation
- Duplicate User Checks
- Username & Email Normalization

---

## 🗄️ Extended Schema

### `users`

- failed_attempts
- is_verified
- locked_until
- role

### `password_resets`

- user_id
- hashed_token
- expires_at

### `email_verifications`

- user_id
- hashed_token
- expires_at

---

## 📡 Additional Endpoints

```bash
GET    /auth/verify-email
POST   /auth/request-password-reset
POST   /auth/reset-password

GET    /admin/users
POST   /admin/{username}/lock
POST   /admin/{username}/unlock
POST   /admin/{username}/role
```

---

## 🧠 Key Concepts Learned

- Stateful authentication architecture
- Secure session lifecycle management
- Replay attack prevention
- RBAC enforcement patterns
- Security-first backend design
- Token rotation strategies
- Real-world authentication workflows
- Validation architecture using Pydantic

---

# 🔴 Level 3 — Auth Platform / Authentication as a Service (In Progress)

## 🎯 Objective

Refactor the authentication system into a modular, scalable authentication platform that can serve multiple applications and services.

---

## 🏗️ Architecture Goals

- Service-Oriented Authentication Architecture
- Reusable Authentication Modules
- Clean Separation of Concerns
- Scalable Project Structure
- Config-Driven Security Architecture

---

## 🔥 Planned Features

### Architecture Refactoring

- Service Layer Refactoring
- Centralized Token Management
- Shared Validation Utilities
- Centralized Security Configuration
- Modular Dependency System

---

### Session & Device Management

- Multi-Device Session Tracking
- Session Dashboard
- Logout from Current / All Devices

---

### Distributed Authentication

- Redis-Based Token Blacklisting
- Distributed Rate Limiting
- Scalable Session Revocation

---

### OAuth & External Identity

- Google OAuth 2.0 Login
- Extensible OAuth Provider System

---

### Observability & Monitoring

- Authentication Audit Logs
- Security Event Tracking
- Login Activity Monitoring

---

### Infrastructure & Deployment

- Dockerized Deployment
- Production PostgreSQL Integration
- Alembic Migrations
- Environment-Based Configuration

---

## 🧠 Key Concepts Learned

- Authentication system design
- Service-oriented backend architecture
- Distributed authentication strategies
- Scalable security infrastructure
- Production deployment workflows
- Modular backend engineering

---

# 🧠 Engineering Approach

This project is designed to be built incrementally:

1. ✅ Complete Level 1 (Core Authentication)
2. 🔄 Extend into Level 2 (Security Architecture)
3. 🏗️ Refactor into Level 3 (Scalable Auth Platform)

---

# ⚠️ Security Best Practices Implemented

- Passwords are hashed using bcrypt
- Refresh tokens are stored as hashed values
- Tokens have proper expiration policies
- Sensitive workflows use time-bound tokens
- Backend enforces all authentication rules
- Role enforcement handled server-side
- Refresh token replay detection implemented

---

# ❌ Common Pitfalls Avoided

- Storing raw refresh tokens
- Missing token expiration
- Weak password handling
- No logout/session invalidation
- Trusting frontend authorization
- Stateless-only refresh token architecture

---

# 📌 Future Improvements

- Two-Factor Authentication (2FA)
- Device fingerprinting
- Risk-based authentication
- Distributed caching
- API Gateway integration
- Frontend migration to React

---

# 📄 License

This project is for educational and demonstration purposes.

---

# 🙌 Final Note

This is not just an authentication project — it is a progressive exploration of backend engineering, security architecture, and scalable system design.

# 🔗 Deployment

- The authentication system is deployed on a DigitalOcean Droplet.
- Production deployment includes:
  - Nginx reverse proxy
  - Uvicorn + Gunicorn application server setup
  - HTTPS/SSL configuration
  - Custom domain integration

**Live URL:**  
https://auth.saxam.dev
