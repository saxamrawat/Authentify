# 🔐 Authentify — Scalable Authentication System

A production-oriented authentication system built with a **progressive architecture**, evolving from a basic JWT-based authentication application into a **secure, scalable authentication platform**.

The project is structured into progressive levels, with each level representing increasing complexity, security, scalability, and real-world applicability.

The goal is not simply to implement authentication, but to **understand and design secure, scalable backend systems through progressive engineering**.

---

# 🚀 Project Overview

AUTHENTIFY demonstrates how an authentication system can evolve from a simple application into a robust authentication platform:

- 🟢 **Level 1 — Core Authentication System**
- 🟡 **Level 2 — Production-Grade Authentication & Security**
- 🔴 **Level 3 — Secure Authentication Core & Distributed Security**
- 🔵 **Level 4 — Authentication Platform & API Productization (Planned)**

The system remains a fully usable authentication application while progressively gaining capabilities that allow it to eventually serve as an authentication platform for external applications.

---

# 🌐 Minimal Frontend

A lightweight frontend is included to interact with and test the authentication system.

## Tech Used

- HTML
- CSS
- JavaScript
- Jinja2 (for serving pages)

## Purpose

- Test registration and login flows
- Simulate real client behavior
- Validate access and refresh token flows
- Test protected routes
- Manage sessions
- Demonstrate the authentication system as a working application

> The frontend is intentionally minimal. A future React frontend can consume the same authentication API.

---

# 🛠️ Tech Stack

- **Framework:** FastAPI
- **Database:** PostgreSQL
- **ORM:** SQLAlchemy
- **Migrations:** Alembic
- **Authentication:** JWT (Access + Refresh Tokens)
- **Password Hashing:** Bcrypt
- **Security State:** Redis / Valkey
- **Token Hashing:** SHA-256
- **Templating:** Jinja2
- **Testing:** Pytest
- **Production Server:** Gunicorn + Uvicorn
- **Reverse Proxy:** Nginx
- **Deployment:** DigitalOcean Droplet
- **HTTPS:** SSL/TLS

---

# 🟢 Level 1 — Core Authentication System

## 🎯 Objective

Build a functional JWT-based authentication system with proper authentication and session-handling fundamentals.

## Status

**COMPLETED**

---

## ✅ Features

- User Registration & Login
- Password Hashing with Bcrypt
- JWT Authentication
  - Access Tokens
  - Refresh Tokens
- Token Refresh Flow
- Logout Endpoint
- Protected Routes
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

    POST   /auth/register
    POST   /auth/login
    POST   /auth/refresh
    POST   /auth/logout
    GET    /auth/me

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

# 🟡 Level 2 — Production-Grade Authentication & Security

## 🎯 Objective

Extend the core authentication system with real-world security architecture and attack-prevention mechanisms.

## Status

**COMPLETED**

---

## 🔐 Features

### Account Security

- Email Verification Flow
- Forgot Password / Reset Password
- Time-Bound Security Tokens
- Account Locking after Failed Login Attempts

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
- Account Locking
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

    GET    /auth/verify-email
    POST   /auth/request-password-reset
    POST   /auth/reset-password

    GET    /admin/users
    POST   /admin/{username}/lock
    POST   /admin/{username}/unlock
    POST   /admin/{username}/role

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

# 🔴 Level 3 — Secure Authentication Core & Distributed Security

## 🎯 Objective

Transform the authentication system into a secure, modular, and distributed authentication core while establishing strong security guarantees through automated testing and security hardening.

## Status

**COMPLETED ✅**

Level 3 represents the completion of the secure authentication core.

The system remains a fully usable application while its backend architecture has been hardened for future API/platform use.

---

# 🏗️ Level 3 Architecture

The system follows a layered architecture:

    Client
      ↓
    FastAPI API
      ↓
    Dependencies
      ↓
    Services
      ├── PostgreSQL Repositories
      └── Redis Infrastructure
              ↓
            Redis

### PostgreSQL

PostgreSQL remains the **authoritative persistent database** for:

- Users
- Sessions
- Refresh tokens
- Persistent security state
- Relationships and integrity constraints

### Redis / Valkey

Redis provides **ephemeral distributed security state** for:

- Token revocation
- Session revocation
- Distributed rate limiting

Redis is not treated as a second PostgreSQL database.

---

# 🔹 Level 3 Phase 1 — Session & Device Management

## Status

**COMPLETED ✅**

Implemented:

- Multi-device session tracking
- Session dashboard
- Current-session identification
- Individual session revocation
- Logout
- Logout-all
- Device information handling
- Session-aware authentication

The authentication system now treats sessions as first-class security objects rather than treating access tokens as completely independent credentials.

---

# 🔹 Level 3 Phase 2 — Token Security & Cryptographic Hardening

## Status

**COMPLETED ✅**

Implemented and verified:

- SHA-256 refresh-token hashing
- Secure token persistence
- Refresh-token rotation
- Refresh-token reuse detection
- Token lifecycle hardening
- Existing JWT `jti` implementation retained and reused
- Token/session security improvements

Raw refresh tokens are never persisted.

---

# 🔹 Level 3 Phase 3 — Redis Token Revocation & Distributed Security

## Status

**COMPLETED ✅**

Implemented:

### Redis Infrastructure

- Redis / Valkey support
- Async Redis client
- Connection pooling
- Connection, socket, and pool timeouts
- Health-check configuration
- FastAPI lifespan integration
- Redis health endpoint
- Redis startup failure handling

### Token Revocation

- JTI-based access-token revocation
- Session-level revocation
- TTL-based revocation entries
- Authentication-oriented `RevocationStore` abstraction

Redis keys:

    auth:revoked:jti:<jti>
    auth:revoked:session:<session_id>

Raw access and refresh tokens are never stored in Redis.

### Distributed Rate Limiting

Implemented Redis-backed distributed login rate limiting using an atomic Lua script.

Current login policy:

    5 requests / 60 seconds
    6th request → HTTP 429

Rate-limit key:

    auth:ratelimit:login:ip:<hashed-ip>

The implementation was verified across multiple Uvicorn workers to confirm shared distributed state.

### Failure Handling

Security-critical Redis checks fail closed where required.

Redis infrastructure errors are translated into application-level exceptions rather than exposing raw Redis errors.

---

# 🔹 Level 3 Phase 4 — Security Testing & Hardening

## Status

**COMPLETED ✅**

Phase 4 established an application-wide automated security baseline.

The phase progressed through:

    Architecture Review
            ↓
    Threat Modeling
            ↓
    Security Invariants
            ↓
    Security Tests
            ↓
    Concurrency Testing
            ↓
    Regression Testing
            ↓
    Integration Verification
            ↓
    Final Security Audit

---

## 🔐 Security Testing Coverage

### Authentication & JWT

- Valid login
- Invalid credentials
- Unverified accounts
- Locked accounts
- Rate-limited accounts
- JWT claims
- JWT expiration
- JWT tampering
- Access-token validation
- Refresh-token identification
- Unique `jti` values
- Authentication-state information leakage

---

### Access Tokens & Sessions

- Missing credentials
- Invalid tokens
- Expired tokens
- Revoked sessions
- Cross-user session access
- Current-session handling
- Individual session revocation
- Logout
- Logout-all
- Access-token behavior after session revocation

Security invariant:

> Revoking a session must prevent that session's credentials from continuing to authorize requests.

---

### Refresh Tokens

- SHA-256 hashing
- Expiration
- Revocation
- Rotation
- Replay
- Reuse detection
- Token substitution
- Cross-user refresh attempts
- Session/token relationships

Security invariant:

> A refresh token can have only one successful consumer.

---

### Transactional Refresh Rotation

Refresh-token rotation now behaves as one logical transaction:

    Consume old refresh token
            ↓
    Create new refresh token
            ↓
    Update session → new refresh token
            ↓
    Update last_active
            ↓
          COMMIT

If any operation fails:

    ROLLBACK

This prevents partially completed refresh rotations.

---

### Concurrency Security

Concurrency testing covers:

- Concurrent refresh-token consumption
- Concurrent refresh rotation
- Concurrent session revocation
- Concurrent logout-all
- Database uniqueness races
- Transaction rollback

A database-level atomic operation ensures that only one concurrent request can successfully consume an active refresh token.

---

### Database Security

Verified:

- Unique usernames
- Unique email addresses
- Unique refresh-token hashes
- One refresh token per session
- Foreign-key relationships
- Session/token integrity
- Required security tables
- Alembic migration state

---

### Authorization

Tested:

- Protected resources
- RBAC
- Admin-only dependencies
- Admin endpoints
- Role enforcement
- Account lock/unlock
- Role changes
- Cross-user resource access

Authorization remains server-side and is never delegated to frontend state.

---

### API Security

Tested:

- Missing authentication
- Invalid UUIDs
- Invalid request bodies
- Invalid credentials
- Username enumeration
- Cross-user access
- Database error leakage
- Token/error-detail leakage
- Unknown user-agent handling

A production defect involving unknown user-agent parsing was discovered and fixed.

Unknown devices now safely fall back to:

    Unknown Device

A security regression test protects this behavior.

---

### Security Regression Suite

Dedicated security regression tests cover high-value security properties including:

- Rate limiter failure must fail closed
- Rate-limited login must not reach authentication logic
- Refresh-token reuse must invalidate the session set
- Failed refresh rotation must leave original credentials valid
- Revoked-session access tokens cannot be reused
- Invalid credentials must not expose authentication state

---

### Integration Testing

Integration tests verify:

- Test database is at the expected Alembic head
- Required security tables exist
- Refresh-token hash constraints exist
- Session/refresh-token relationship is unique
- Tests cannot accidentally use the production database

---

# 🧪 Test Isolation

The test environment uses dedicated infrastructure.

### PostgreSQL

    authentication_project_test

### Redis

    redis://localhost:6379/15

Application Redis remains isolated from test Redis.

Tests also use:

- Dedicated PostgreSQL test database
- Database cleanup
- Redis cleanup
- FastAPI dependency overrides
- Environment-specific configuration

---

# 📊 Level 3 Security Baseline

Final Phase 4 verification:

    101 tests passed
    3 known deprecation warnings

The warnings are technical-debt items and are not security failures.

Known warnings concern:

- SQLAlchemy `declarative_base()` deprecation
- Pydantic class-based `Config` in `SessionResponse`
- Pydantic class-based `Config` in `SessionDetailsResponse`

---

# 🚀 Level 3 Deployment Milestone

Level 3 represents the completion of the secure authentication core.

The completed Level 3 version is intended to be deployed as the first stable milestone of AUTHENTIFY.

### Level 3 Milestone

    AUTHENTIFY v1.0
    Secure Authentication Core

The deployed application remains a fully usable authentication application with:

- Registration
- Login
- Email verification
- Password reset
- JWT authentication
- Refresh-token rotation
- Session management
- Multi-device sessions
- Logout
- Logout-all
- RBAC
- Admin functionality
- Redis revocation
- Distributed rate limiting
- Security hardening
- Automated security testing

Deployment marks the end of Level 3 rather than the end of AUTHENTIFY's development.

---

# 🔵 Level 4 — Authentication Platform & API Productization

## Status

**PLANNED**

Level 4 evolves AUTHENTIFY from a secure authentication application into a reusable authentication platform that external applications can consume.

The existing application and frontend remain usable.

API productization is an **addition and selective refactoring of the existing system**, not a replacement of the application.

---

## 🎯 Level 4 Objective

Make AUTHENTIFY consumable by external applications through a clearly defined, secure, documented API.

The goal is to allow another application to use AUTHENTIFY for:

- Registration
- Authentication
- Email verification
- Password reset
- Access-token management
- Refresh-token management
- Session management
- Logout
- Authorization

The existing authentication core remains responsible for the underlying security.

---

## 🌐 Public API

Planned work includes:

- Public API boundary
- API versioning
- Consistent request/response contracts
- Authentication API design
- Session API design
- Token API design
- Error-response contracts
- OpenAPI documentation
- Consumer integration examples
- API security hardening
- CORS configuration
- API test coverage

A future external application should be able to interact with AUTHENTIFY approximately as:

    External Application
            ↓
       AUTHENTIFY API
            ↓
     Authentication Core
            ↓
       ┌────┴────┐
       ↓         ↓
    PostgreSQL  Redis

---

# 🔥 Level 4 Planned Features

## 🌐 API & Platform

- Public Authentication API
- API Versioning
- API Documentation
- OpenAPI Integration
- External Application Integration
- Stable Error Contracts
- Consumer-Facing Authentication Flow

---

## 🔑 OAuth & External Identity

- Google OAuth 2.0 Login
- Extensible OAuth Provider System
- OpenID Connect exploration

---

## 🔐 Advanced Authentication

- Two-Factor Authentication (2FA)
- Device Fingerprinting
- Risk-Based Authentication
- Advanced Session Security

---

## 📊 Observability & Security Monitoring

- Authentication Audit Logs
- Security Event Tracking
- Login Activity Monitoring
- Security Event Analysis

---

## 🏗️ Infrastructure & Production Hardening

- Dockerized Deployment
- Production Infrastructure Improvements
- Advanced Redis/PostgreSQL hardening
- Environment-based configuration improvements
- Deployment automation
- Production monitoring

---

# 🧠 Engineering Approach

AUTHENTIFY is designed to evolve incrementally:

    Level 1
    Core Authentication
            ↓
    Level 2
    Production Security
            ↓
    Level 3
    Secure Authentication Core
            ↓
    Deployment / v1.0
            ↓
    Level 4
    Authentication Platform
            ↓
    Future Advanced Authentication

Each level builds on the previous one rather than replacing it.

---

# 🔐 Security Principles

AUTHENTIFY follows these core security principles:

- Passwords are securely hashed
- Refresh tokens are stored only as hashes
- SHA-256 is used for refresh-token hashing
- Raw access/refresh tokens are never stored in Redis
- Tokens have explicit expiration policies
- Security tokens are time-bound
- Authentication is enforced server-side
- Authorization is enforced server-side
- Refresh-token rotation is implemented
- Refresh-token reuse detection is implemented
- Session revocation is supported
- Access-token revocation is supported
- Redis security checks fail closed where required
- Rate limiting is distributed
- Security-sensitive database operations are concurrency-safe
- Security invariants are protected by automated tests
- Production database and test database are isolated

---

# ❌ Common Pitfalls Avoided

- Storing raw refresh tokens
- Missing token expiration
- Weak password handling
- Stateless-only refresh-token architecture
- Missing session invalidation
- Trusting frontend authorization
- Ignoring refresh-token replay
- Non-atomic refresh-token rotation
- Non-atomic security-sensitive operations
- Silently bypassing rate limiting when Redis fails
- Exposing internal infrastructure errors
- Allowing cross-user resource access
- Running security tests against production infrastructure

---

# 📌 Future Improvements

Potential future work includes:

- OAuth 2.0
- OpenID Connect
- Google authentication
- Two-Factor Authentication
- Advanced device fingerprinting
- Risk-based authentication
- Authentication audit logging
- Security event monitoring
- Dockerized deployment
- API gateway integration
- React frontend
- Further distributed-system hardening

---

# 📄 License

This project is for educational and demonstration purposes.

---

# 🙌 Final Note

AUTHENTIFY is not simply an authentication project.

It is a progressive exploration of:

- Backend engineering
- Authentication architecture
- Security engineering
- Distributed systems
- Database design
- Concurrency
- API design
- Testing
- Production deployment
- Scalable system architecture

The project intentionally evolves in stages so that each layer of complexity can be understood, implemented, tested, and hardened before moving to the next.

---

# 🔗 Deployment

AUTHENTIFY is deployed on a DigitalOcean Droplet.

Production deployment includes:

- Nginx reverse proxy
- Uvicorn + Gunicorn application server setup
- HTTPS/SSL configuration
- Custom domain integration
- PostgreSQL
- Redis / Valkey

**Live URL:**

https://auth.saxam.dev

The deployed version represents the **Level 3 secure authentication core / v1.0 milestone**.

Level 4 development will extend this deployed application with public API and authentication-platform capabilities.