# NestJS Authentication

<p align="center">
  <a href="http://nestjs.com/" target="blank"><img src="https://nestjs.com/img/logo-small.svg" width="200" alt="Nest Logo" /></a>
</p>

![Version](https://img.shields.io/github/v/tag/Md-Tarikul-Islam-Juel/nestJS_Authentication?label=version&color=blue)
![Release](https://img.shields.io/github/v/release/Md-Tarikul-Islam-Juel/nestJS_Authentication?label=release&color=blue)
![Issues](https://img.shields.io/github/issues/Md-Tarikul-Islam-Juel/nestJS_Authentication?color=red)

<div align="center">
  <h1 style="font-size: 36px;"><strong>The Ultimate & Ready To Go Solution For User Management System</strong></h1>
</div>

The **NestJS Authentication Boilerplate** is a robust and flexible solution for implementing user authentication in your
**NestJS** projects. Empowering you with a rich feature set, it simplifies the process of managing user sign-up,
sign-in, email OTP verification, password recovery, and more.

## 🚀 Key Features: Boost your project speed

| Feature                         | Description                                                                                                | API Type | JWT Token Protection |
| ------------------------------- | ---------------------------------------------------------------------------------------------------------- | :------: | :------------------: |
| **Sign-Up & Login APIs**        | Streamline user onboarding with a smooth and intuitive registration and login experience.                  |   REST   |          No          |
| **Email Verification API**      | Boost security and prevent unauthorized access through email OTP verification with lockout protection.     |   REST   |          No          |
| **MFA Support**                 | Multi-factor authentication via email OTP for enhanced security during sign-in.                            |   REST   |          No          |
| **OTP Resend API**              | Never let users get stuck! Offer convenient OTP resend options for seamless account activation.            |   REST   |          No          |
| **Forget Password API**         | Forget passwords? No problem! Our secure recovery process helps users regain access quickly.               |   REST   |          No          |
| **Change Password API**         | Take control of your account security with effortless password changes.                                    |   REST   |         Yes          |
| **Refresh Token API**           | Securely refresh access tokens with JTI tracking and session rotation strategies.                          |   REST   |         Yes          |
| **Logout API**                  | Log users out of all devices by revoking all active sessions with Redis-backed session management.         |   REST   |         Yes          |
| **Track User Last Active Time** | Capture the timestamp of the last time a user was active in the application.                               |   REST   |         Yes          |
| **OAuth 2.0**                   | Sign-in with Google and Facebook OAuth providers (configure your OAuth console to get credentials).        |   REST   |          No          |
| **Soft Delete Pattern**         | User accounts support soft deletion, allowing email reuse while maintaining data integrity.                |          |                      |

## 🌟 Technology Stack: Built with Modern Tools

### Core Framework & Architecture
- **Framework:** [NestJS](https://nestjs.com/) - Progressive Node.js framework
- **Architecture:** Clean Architecture with Domain-Driven Design (DDD)
  - **Application Layer:** Use cases and business logic orchestration
  - **Domain Layer:** Core business entities and rules
  - **Infrastructure Layer:** External services, adapters, and implementations
  - **Interface Layer:**  controllers, and API contracts

### Database & Caching
- **Database:** [PostgreSQL](https://www.postgresql.org/) - Robust relational database
- **Cache:** [Redis](https://redis.io/) - High-performance in-memory caching and session storage
- **ORM:** [Prisma](https://www.prisma.io) - Type-safe database client with migrations


### Security & Authentication
- **Token Management:** JWT (JWS + JWE)
  - [JWS](https://tools.ietf.org/html/rfc7515) for signed tokens
  - [JWE](https://tools.ietf.org/html/rfc7516) for encrypted tokens

- **Password Hashing:** [bcrypt](https://github.com/kelektiv/node.bcrypt.js) with configurable salt rounds
- **OAuth 2.0:** [Google](https://developers.google.com/identity/protocols/oauth2) and [Facebook](https://developers.facebook.com/docs/facebook-login/) integration
- **Security Features:**
  - Rate Limiting with Redis-backed throttler
  - DDoS Protection with configurable thresholds
  - Geolocation-based access control
  - IP whitelisting/blacklisting
  - CORS configuration
  - Helmet.js for HTTP headers security
  - CSRF protection
  - SSRF (Server-Side Request Forgery) protection

### Validation & Documentation
- **DTO Validation:** [class-validator](https://github.com/typestack/class-validator) and [class-transformer](https://github.com/typestack/class-transformer)
- **API Documentation:** [Swagger](https://swagger.io/) with OpenAPI 3.0 specification
- **APIs:** REST API and GraphQL (Apollo Server)

### Infrastructure & DevOps
- **Containerization:** Docker & Docker Compose
- **Logging:** [Winston](https://github.com/winstonjs/winston) with daily log rotation
- **Queue Management:** [BullMQ](https://docs.bullmq.io/) for background job processing


## 🔗 API Endpoints

Below are the key authentication API endpoints for this project:

### Auth

- **Sign-Up Endpoint:** `{{url}}/auth/signup` - Sign up user
- **Sign-In Endpoint:** `{{url}}/auth/signin` - Sign in user
- **Verify OTP Endpoint:** `{{url}}/auth/verify` - Verify OTP
- **Resend OTP Endpoint:** `{{url}}/auth/resend` - Resend OTP email
- **Forget Password Endpoint:** `{{url}}/auth/forget-password` - Forget password OTP email send
- **Change Password Endpoint:** `{{url}}/auth/change-password` - Change user password (JWT protected)
- **Refresh Token Endpoint:** `{{url}}/auth/refresh-token` - Refresh access token (JWT protected)
- **Logout Endpoint:** `{{url}}/auth/logout-all` - Logout from all devices (JWT protected)
- **Start Google OAuth Flow Endpoint:** `{{url}}/auth/google` - Start Google OAuth flow
- **Google OAuth Callback Endpoint:** `{{url}}/auth/google/callback` - Google OAuth callback
- **Start Facebook OAuth Flow Endpoint:** `{{url}}/auth/facebook` - Start Facebook OAuth flow
- **Facebook OAuth Callback Endpoint:** `{{url}}/auth/facebook/callback` - Facebook OAuth callback

## 📂 Project Structure

The project follows **Clean Architecture** principles with a clear separation of concerns:

```
src/
├─ main.ts                                       # Bootstrap: DI container, global middlewares/filters/pipes
├─ app.module.ts                                 # Root module (wires cross-cutting modules)
├─ app-http.module.ts                            # HTTP composition root (controllers, filters, interceptors)

├─ config/                                       # Typed config, env validation, DI tokens
│  ├─ config.module.ts                           # Loads/validates env; exposes ConfigService globally
│  ├─ env.schema.ts                              # class-validator schema for process.env
│  ├─ tokens.ts                                  # IoC tokens (ports/adapters, buses, stores)
│  └─ defaults.ts                                # Sensible defaults (timeouts, limits, pagination caps)

├─ common/                                       # Cross-cutting concerns (reused everywhere)
│  ├─ http/
│  │  ├─ filters/
│  │  │  └─ problem-details.filter.ts            # RFC7807 mapper
│  │  ├─ interceptors/
│  │  │  ├─ logging.interceptor.ts               # Structured request logs (method, path, latency, reqId)
│  │  │  ├─ timeout.interceptor.ts               # Request timeout guardrail
│  │  │  └─ version-deprecation.interceptor.ts   # API version deprecation warnings
│  │  ├─ guards/                                 # HTTP guards (RBAC/ABAC), auth checks
│  │  └─ pipes/
│  │     └─ validation.pipe.ts                   # Global ValidationPipe config
│  ├─ security/
│  │  ├─ helmet.ts                               # Secure headers for HTTP endpoints
│  │  ├─ rate-limiter.ts                         # Throttling config (Redis-backed)
│  │  ├─ cors.ts                                 # CORS allowlist configuration
│  │  ├─ geolocation.service.ts                  # Geolocation-based access control
│  │  ├─ ip-control.service.ts                   # IP whitelisting/blacklisting
│  │  └─ ssrf-protection.service.ts              # SSRF prevention
│  ├─ observability/
│  │  └─ logger.module.ts                        # Winston logger with daily rotation
│  ├─ errors/
│  │  ├─ domain-error.ts                         # Base domain error (no transport coupling)
│  │  └─ error-codes.ts                          # Uniform error codes (stable identifiers)
│  ├─ persistence/
│  │  └─ pagination.ts                           # Offset/cursor helpers (sort keys, nextCursor)
│  ├─ auth/
│  │  └─ strategies/                             # Cross-cutting auth guards (JWT, OAuth, etc.)
│  │     ├─ access-token.strategy.ts             # Access token guard (HTTP)
│  │     ├─ refresh-token.strategy.ts            # Refresh token guard with logout validation
│  │     └─ logout-token-validate.service.ts     # Token revocation validation
│  ├─ guards/
│  │  ├─ ddos-protection.guard.ts                # DDoS protection guard
│  │  ├─ geolocation.guard.ts                    # Geolocation guard
│  │  ├─ ip-control.guard.ts                     # IP control guard
│  │  └─ throttler-proxy.guard.ts                # Rate limiting guard
│  └─ decorators/
│     └─ public.decorator.ts                     # Public route decorator (skip auth)

├─ modules/                                      # All bounded contexts (DDD modules)
│
│  ├─ _shared/                                   # Shared utilities across modules (NOT business logic)
│  │  └─ constants.ts                            # Constants reused inside modules
│
│  ├─ auth/                                      # Bounded Context: Authentication Domain
│  │
│  │  ├─ domain/                                 # PURE Domain Layer (no NestJS, no Prisma, no HTTP)
│  │  │  ├─ entities/                            # Domain Entities → define state + invariants
│  │  │  │  └─ user.entity.ts
│  │  │  ├─ value-objects/                       # Immutable value objects (Email, Password, etc.)
│  │  │  │  ├─ email.vo.ts
│  │  │  │  └─ password.vo.ts
│  │  │  ├─ enums/                               # Domain enumerations
│  │  │  │  └─ login-source.enum.ts
│  │  │  ├─ events/                              # Domain events (past-tense: UserRegistered)
│  │  │  ├─ repositories/                        # Repository PORTS (interfaces — no implementation)
│  │  │  │  ├─ user.repository.port.ts           # User repository port
│  │  │  │  ├─ email.service.port.ts             # Email service port (for sending OTP emails)
│  │  │  │  ├─ otp-cache.port.ts                 # OTP cache port (for storing/retrieving OTPs)
│  │  │  │  ├─ activity-cache.port.ts            # Activity cache port (for tracking user activity)
│  │  │  │  ├─ jwt-service.port.ts               # JWT service port (for token generation)
│  │  │  │  └─ logger.port.ts                    # Logger port (for application logging)
│  │  │  └─ errors/                              # Domain-specific exceptions (business rule violations)
│  │  │     ├─ account-locked.error.ts
│  │  │     ├─ cache-error.error.ts
│  │  │     ├─ email-already-exists.error.ts
│  │  │     ├─ email-service-error.error.ts
│  │  │     ├─ invalid-credentials.error.ts
│  │  │     ├─ invalid-otp.error.ts
│  │  │     ├─ user-not-found.error.ts
│  │  │     └─ user-not-verified.error.ts
│  │
│  │  ├─ application/                            # Application Layer (Use-Cases) — Orchestrates domain
│  │  │  ├─ di-tokens.ts                         # Dependency Injection tokens for ports
│  │  │  ├─ services/                            # Application Services (business logic, utilities)
│  │  │  │  ├─ auth.service.ts                   # Main application service (orchestrates use-cases)
│  │  │  │  ├─ common-auth.service.ts            # Common auth utilities (data/token sanitization)
│  │  │  │  ├─ user.service.ts                   # User operations service
│  │  │  │  ├─ otp.service.ts                    # OTP operations service
│  │  │  │  ├─ otp-domain.service.ts             # OTP generation domain service
│  │  │  │  ├─ password-policy.service.ts        # Password hashing service
│  │  │  │  ├─ password-validation.service.ts    # Password validation business logic
│  │  │  │  ├─ last-activity-track.service.ts    # User activity tracking service
│  │  │  │  └─ logout.service.ts                 # Logout operations service
│  │  │  ├─ dto/                                 # Data Transfer Objects (request/response)
│  │  │  │  ├─ auth-request.dto.ts               # Request DTOs (SignupDto, SigninDto, etc.)
│  │  │  │  ├─ auth-response.dto.ts              # Response DTOs (Success/Error responses)
│  │  │  │  └─ auth-base.dto.ts                  # Base DTOs (Tokens, BaseResponseDto)
│  │  │  ├─ commands/                            # Write-side operations (state-changing commands)
│  │  │  │  ├─ register-user.command.ts
│  │  │  │  ├─ sign-in.command.ts
│  │  │  │  ├─ verify-otp.command.ts
│  │  │  │  ├─ resend-otp.command.ts
│  │  │  │  ├─ forget-password.command.ts
│  │  │  │  ├─ change-password.command.ts
│  │  │  │  ├─ refresh-token.command.ts
│  │  │  │  └─ oauth-sign-in.command.ts
│  │  │  ├─ use-cases/                           # Application use-cases (orchestrate commands & domain)
│  │  │  │  ├─ register-user.use-case.ts
│  │  │  │  ├─ sign-in.use-case.ts
│  │  │  │  ├─ verify-otp.use-case.ts
│  │  │  │  ├─ resend-otp.use-case.ts
│  │  │  │  ├─ forget-password.use-case.ts
│  │  │  │  ├─ change-password.use-case.ts
│  │  │  │  ├─ refresh-token.use-case.ts
│  │  │  │  ├─ oauth-sign-in.use-case.ts
│  │  │  │  └─ token-config.factory.ts           # Token configuration factory
│  │  │  ├─ mappers/                             # Domain ↔ DTO/View mapping (no ORM, pure mapping)
│  │  │  │  └─ user.mapper.ts
│  │  │  └─ types/                               # Application-specific types
│  │  │     └─ auth.types.ts
│  │
│  │  ├─ infrastructure/                         # Infrastructure Layer (Adapters to technologies)
│  │  │  ├─ prisma/                              # Prisma persistence layer implementations
│  │  │  │  ├─ user.prisma.mapper.ts             # Maps Prisma models ↔ Domain Entities
│  │  │  │  └─ user.prisma.repository.ts         # Repository adapter (implements UserRepositoryPort)
│  │  │  ├─ cache/                               # Cache adapters (Redis implementations)
│  │  │  │  ├─ otp.cache.ts                      # OTP cache adapter (implements OtpCachePort)
│  │  │  │  └─ activity.cache.ts                 # Activity cache adapter (implements ActivityCachePort)
│  │  │  ├─ oauth-strategies/                    # OAuth provider strategies (Facebook, Google)
│  │  │  │  ├─ facebook.strategy.ts              # Passport Facebook strategy
│  │  │  │  └─ google.strategy.ts                # Passport Google strategy
│  │  │  ├─ adapters/                            # Infrastructure adapters
│  │  │  │  ├─ email.adapter.ts                  # Email service adapter (implements EmailServicePort)
│  │  │  │  ├─ jwt.adapter.ts                    # JWT adapter (implements JwtServicePort)
│  │  │  │  ├─ logger.adapter.ts                 # Logger adapter (implements LoggerPort)
│  │  │  │  ├─ otp-generator.adapter.ts          # OTP generation adapter
│  │  │  │  └─ password.adapter.ts               # Password hashing adapter
│  │  │  └─ repositories/                        # Repository implementations
│  │  │     └─ user.repository.ts                # User repository implementation
│  │
│  │  └─ interface/                              # Delivery Layer (No business logic)
│  │     ├─ http/                                # REST API Adapters (Controllers)
│  │     │  ├─ auth.controller.ts                # HTTP endpoints → call use-cases only (thin layer)
│  │     │  └─ interceptors/                     # HTTP interceptors
│  │     │     └─ track-last-activity.interceptor.ts
│  │     └─ validators/                          # Framework adapters (class-validator decorators)
│  │        ├─ password-validator.class.ts       # Thin adapter delegating to PasswordValidationService
│  │        └─ password-decorator.decorator.ts   # Decorator factory for @PasswordValidation()
│  │
│  └─ dev/                                       # Development tools (only in dev mode)
│     ├─ dev.module.ts                           # Dev module (conditionally loaded)
│     ├─ dev-otp-viewer.controller.ts            # OTP viewer for testing
│     └─ templates/
│        └─ otp-viewer.hbs                       # OTP viewer HTML template

├─ health/
│  └─ health.controller.ts                       # /health /ready /live probes (HTTP)

└─ platform/                                     # Concrete infrastructure wiring
   ├─ prisma/
   │  ├─ prisma.module.ts                        # Registers Prisma + repository bindings
   │  └─ prisma.service.ts                       # Prisma Client service
   ├─ jwt/                                       # JWT token infrastructure
   │  ├─ jwt.module.ts                           # JWT module configuration
   │  └─ jwt.service.ts                          # Token generation/validation service
   ├─ redis/                                     # Redis client module
   │  ├─ redis.module.ts                         # Redis module configuration
   │  └─ redis.service.ts                        # Redis client service
   └─ queue/                                     # BullMQ queue setup
      └─ queue.module.ts                         # Queue module configuration
```

### Key Architecture Principles

- **Dependency Inversion**: High-level modules don't depend on low-level modules
- **Port-Adapter Pattern**: Infrastructure adapters implement domain interfaces
- **Use Case Driven**: Business logic encapsulated in use cases


## 🧪 Development Features

### OTP Viewer (Development Only)

For easier testing during development, the application includes an OTP viewer accessible at:

**Endpoint:** `http://localhost:3000/dev/otps`

**Features:**
- Real-time display of all generated OTPs
- Countdown timer showing OTP expiration
- Click-to-copy functionality with toast notifications
- Professional UI with modern design
- Automatically displays OTPs from:
  - Sign-up verification
  - Sign-in MFA
  - Password recovery
  - OTP resend requests

**Note:** This feature is only available when `NODE_ENV=development` and is automatically disabled in production.

### Health Check Endpoints

Monitor application health and dependencies:

- **Health Check:** `http://localhost:3000/health`
- Monitors database connectivity
- Checks Redis availability
- Reports overall system status

## 📁 Project contents:

- **Code**: Contains the source code for your project, including all necessary files and modules.
- **Postman Collection**: Provides pre-configured requests for testing and interacting with your API endpoints in
  documents folder.
- **Swagger Documentation (API Documentation)**:
  Generates interactive documentation describing your API endpoints, request parameters, response formats, and
  authentication methods.
  Accessible at **http://localhost:3000/api**

## 🚴🏿 Setup Instructions:

### Prerequisites

- **Node.js** (v16 or higher)
- **Docker** and **Docker Compose**
- **npm** or **yarn** package manager

### Installation Steps

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/Md-Tarikul-Islam-Juel/nestJS_Authentication.git
   cd nestJS_Authentication
   ```

2. **Install Dependencies:**

   ```bash
   npm install
   # or
   yarn install
   ```

3. **Create Environment File:**

   - Copy `.env.example` to `.env` in the root directory
   - Modify the variables in `.env` according to your configuration
   
   ```bash
   cp .env.example .env
   ```

4. **Start Docker Containers:**

   Start PostgreSQL and Redis containers:

   ```bash
   docker-compose -f docker-compose-dev.yml up -d
   ```

   This will start:
   - PostgreSQL database on port 5432
   - Redis cache on port 6379

5. **Generate Prisma Client:**

   ```bash
   npx prisma generate
   ```

6. **Run Database Migrations:**

   ```bash
   npx prisma migrate deploy
   ```

7. **Start the Application:**

   Development mode with hot reload:
   ```bash
   npm run start:dev
   # or
   yarn start:dev
   ```

   Production mode:
   ```bash
   npm run build
   npm run start:prod
   ```

8. **Access the Application:**

   - **API:** `http://localhost:3000`
   - **Swagger Documentation:** `http://localhost:3000/api`
   - **OTP Viewer (Dev only):** `http://localhost:3000/dev/otps`
   - **Health Check:** `http://localhost:3000/health`

9. **Import Postman Collection (Optional):**

   - Locate `nestJs_Authentication.postman_collection.json` in `documents/postman/`
   - Import the collection into Postman for easy API testing

### Docker Commands

```bash
# Start containers
docker-compose -f docker-compose-dev.yml up -d

# Stop containers
docker-compose -f docker-compose-dev.yml down

# View logs
docker-compose -f docker-compose-dev.yml logs -f

# Restart containers
docker-compose -f docker-compose-dev.yml restart
```


## 🌐 Environment Setup

To configure the environment variables for this project, create a `.env` file in the root directory of your project and add the following variables according to your data:

```bash
# ============================================================================
# App Configuration
# ============================================================================
NODE_ENV=development  # development, production, test
PORT=3000
LOG_LEVEL=debug       # error, warn, info, debug

# ============================================================================
# Database Configuration
# ============================================================================
DATABASE_HOST=localhost
DATABASE_USER=juel
DATABASE_PASSWORD=123
DATABASE_PORT=5432
DATABASE_NAME=nest
DATABASE_URL=postgresql://${DATABASE_USER}:${DATABASE_PASSWORD}@${DATABASE_HOST}:${DATABASE_PORT}/${DATABASE_NAME}?schema=public
CONTAINER_NAME=Auth_postgres_NEW

# ============================================================================
# Redis Configuration
# ============================================================================
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_CACHE_EXPIRATION=3600
REDIS_CONTAINER_NAME=Auth_redis_NEW

# ============================================================================
# OTP (One-Time Password) Email Security Configuration
# ============================================================================
OTP_EXPIRE_TIME=5                # OTP expiration time in minutes
OTP_MAX_FAILED_ATTEMPTS=5        # Maximum failed OTP attempts before lockout
OTP_LOCKOUT_TIME=5               # Account lockout duration in minutes
OTP_SENDER_MAIL_HOST=smtp.office365.com
OTP_SENDER_MAIL_PORT=587
OTP_SENDER_MAIL="verification@xyz.com"
OTP_SENDER_MAIL_PASSWORD="12345"

# ============================================================================
# Google OAuth Configuration
# ============================================================================
GOOGLE_CLIENT_ID=1234567890123-8l6478svqjujtfuhv3p1234567890123.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-flK5CKyqQ1DEb112345678901-O0
GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback

# ============================================================================
# Facebook OAuth Configuration
# ============================================================================
FACEBOOK_CLIENT_ID=123456789012345
FACEBOOK_CLIENT_SECRET=f5df32076a1234567890159dfd854c7d
FACEBOOK_CALLBACK_URL=http://localhost:3000/auth/facebook/callback

# ============================================================================
# JWT and JWE Secret Keys
# JSON Web Encryption (JWE). Each key should be exactly 32 characters long,
# ensuring they are 256 bits when properly encoded.
# USE_JWE: Enable/disable JWE encryption. When 'true', tokens are encrypted with JWE.
#          When 'false', plain JWT tokens are generated (default: true).
# ============================================================================
USE_JWE=true
JWE_ACCESS_TOKEN_SECRET=1234567890abcdef1234567890abcdef
JWT_ACCESS_TOKEN_SECRET=abcdefghijklmnopqrstuvwxyza123456
JWE_REFRESH_TOKEN_SECRET=abcdef1234567890abcdef1234567890
JWT_REFRESH_TOKEN_SECRET=abcdefghijklmnopqrstuvwxz1234567

# ============================================================================
# Token Expiration Configuration
# ============================================================================
JWE_JWT_ACCESS_TOKEN_EXPIRATION=86400s    # 24 hours
JWE_JWT_REFRESH_TOKEN_EXPIRATION=30d      # 30 days

# ============================================================================
# JTI / Session Rotation Controls
# ============================================================================
REFRESH_JTI_STRATEGY=uuid           # uuid | nanoid | random-bytes
REFRESH_JTI_LENGTH=21               # length for nanoid/random-bytes (typical: 21)
REFRESH_JTI_PREFIX=                 # optional prefix for jti (e.g., rjti_)
SESSION_ID_PREFIX=sid_              # session id prefix (e.g., sid_)
AUTH_REDIS_PREFIX=auth:             # Redis key prefix (e.g., auth:)
REFRESH_REUSE_POLICY=revoke_session # revoke_session | revoke_all | lock_user
AUTH_NO_STORE=true                  # send Cache-Control: no-store on auth routes

# ============================================================================
# Password Validation Configuration
# ============================================================================
BCRYPT_SALT_ROUNDS=14
PASSWORD_MIN_LENGTH=8
PASSWORD_MAX_LENGTH=20
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBERS=true
PASSWORD_REQUIRE_SPECIAL_CHARACTERS=true
PASSWORD_DISALLOW_REPEATING=false
PASSWORD_DISALLOW_SEQUENTIAL=false
PASSWORD_BLACKLIST_COMMON=false
PASSWORD_EXCLUDE_USERNAME=true

# ============================================================================
# CORS Configuration
# ============================================================================
CORS_ALLOWED_ORIGINS=http://localhost:3000,http://localhost:4200
CORS_ALLOWED_ORIGIN_REGEX=
CORS_ALLOW_ORIGIN_WILDCARD=false
CORS_ALLOW_CREDENTIALS=true
CORS_ALLOWED_METHODS=GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS
CORS_ALLOWED_HEADERS=Authorization,Content-Type,X-Requested-With,X-Internal-Api-Key

# ============================================================================
# Rate Limiting Configuration
# ============================================================================
THROTTLE_TTL=60000      # 60,000 milliseconds = 60 seconds
THROTTLE_LIMIT=100      # Maximum 100 requests per 60 seconds

# ============================================================================
# Geolocation-Based Access Control
# ============================================================================
GEO_ENABLED=true
GEO_ALLOWED_COUNTRIES=US,CA,AU,BD  # Comma-separated country codes

# ============================================================================
# DDoS Protection Configuration
# ============================================================================
DDOS_MAX_REQUESTS=1000    # Max 1000 requests per window
DDOS_WINDOW_SIZE=60       # 60 second window
DDOS_BLOCK_DURATION=3600  # Block for 1 hour (3600 seconds)
```

## 🛡️ Security Features

This boilerplate includes enterprise-grade security features that can be configured via environment variables:

### 1. **Token Management (JWE & JWS)**
- **Dual Token Strategy**: Support for both JWE (encrypted) and JWS (signed) tokens
- **JWE (JSON Web Encryption)**: Provides confidentiality by encrypting token payload
- **JWS (JSON Web Signature)**: Provides integrity and authenticity through digital signatures
- **Configurable Strategy**: Toggle between JWE and JWS via `USE_JWE` environment variable
- **Separate Secrets**: Different secrets for access and refresh tokens
- Configuration: `USE_JWE`, `JWE_ACCESS_TOKEN_SECRET`, `JWT_ACCESS_TOKEN_SECRET`

### 2. **Session Management & Token Rotation**
- **JTI (JWT ID) Tracking**: Unique identifier for each refresh token
- **Redis-Backed Sessions**: All active sessions stored in Redis for instant revocation
- **Session Rotation Strategies**: 
  - `revoke_session`: Revoke only the reused session
  - `revoke_all`: Revoke all sessions for the user
  - `lock_user`: Lock the user account on token reuse
- **Session Indexing**: Track all user sessions for multi-device logout
- **Configurable JTI Generation**: Support for UUID, nanoid, or random-bytes strategies
- Configuration: `REFRESH_JTI_STRATEGY`, `REFRESH_REUSE_POLICY`, `SESSION_ID_PREFIX`

### 3. **Rate Limiting**
- **Redis-backed distributed rate limiting**: Consistent across multiple instances
- **Configurable request limits per time window**: Prevent API abuse
- **Adaptive rate limiting**: Different limits for different endpoints
- **Prevents brute force attacks**: Automatic blocking after threshold
- Configuration: `THROTTLE_TTL`, `THROTTLE_LIMIT`

### 4. **DDoS Protection**
- **Request threshold monitoring**: Track requests per IP
- **Automatic IP blocking**: Block suspicious traffic patterns
- **Configurable block duration**: Temporary or long-term blocks
- **Window-based detection**: Sliding window for accurate detection
- Configuration: `DDOS_MAX_REQUESTS`, `DDOS_WINDOW_SIZE`, `DDOS_BLOCK_DURATION`

### 5. **Geolocation-Based Access Control**
- **Country-level whitelisting**: Restrict access by geographic location
- **Automatic IP geolocation lookup**: Real-time location detection
- **Configurable country codes**: Easy to update allowed countries
- **Bypass for development**: Disable in development environments
- Configuration: `GEO_ENABLED`, `GEO_ALLOWED_COUNTRIES`

### 6. **IP Control**
- **IP whitelisting**: Allow specific IPs to bypass restrictions
- **IP blacklisting**: Block malicious IPs permanently
- **Flexible IP-based access management**: Fine-grained control
- **Integration with other security layers**: Works with rate limiting and DDoS protection

### 7. **CORS (Cross-Origin Resource Sharing)**
- **Fine-grained origin control**: Specify exact allowed origins
- **Regex pattern matching**: Support for dynamic origin patterns
- **Configurable allowed methods and headers**: Control HTTP methods and headers
- **Credential support configuration**: Enable/disable credentials
- Configuration: `CORS_ALLOWED_ORIGINS`, `CORS_ALLOWED_METHODS`, `CORS_ALLOWED_HEADERS`

### 8. **HTTP Security Headers (Helmet.js)**
- **XSS Protection**: Prevent cross-site scripting attacks
- **Clickjacking Protection**: X-Frame-Options header
- **MIME-sniffing Protection**: X-Content-Type-Options header
- **Strict Transport Security**: Force HTTPS connections
- **Content Security Policy**: Control resource loading

### 9. **CSRF Protection**
- **Token-based validation**: Prevent cross-site request forgery
- **State-changing operation protection**: Secure POST/PUT/DELETE requests
- **Double-submit cookie pattern**: Additional layer of protection

### 10. **SSRF Protection**
- **URL validation for external requests**: Prevent internal network exploitation
- **Private IP blocking**: Block requests to internal IPs
- **DNS rebinding protection**: Prevent DNS-based attacks
- **Whitelist-based approach**: Only allow known safe domains

### 11. **OTP Security**
- **Account lockout mechanism**: Lock account after failed attempts
- **Configurable lockout duration**: Temporary account suspension
- **OTP expiration**: Time-limited OTP validity
- **Failed attempt tracking**: Monitor and log failed attempts
- Configuration: `OTP_MAX_FAILED_ATTEMPTS`, `OTP_LOCKOUT_TIME`, `OTP_EXPIRE_TIME`

### 12. **Password Security**
- **Bcrypt hashing**: Industry-standard password hashing
- **Configurable salt rounds**: Adjust computational cost
- **Comprehensive validation rules**: Enforce password complexity
- **Username exclusion**: Prevent username in password
- **Common password blacklisting**: Block weak passwords
- Configuration: `BCRYPT_SALT_ROUNDS`, `PASSWORD_MIN_LENGTH`, `PASSWORD_REQUIRE_*`

### 13. **Soft Delete Pattern**
- **Data retention**: Preserve user data for audit purposes
- **Email reuse support**: Allow email reuse after soft deletion
- **Unique constraint handling**: Partial unique index for active users
- **Audit trail**: Track deletion timestamps

<br/><br/><br/>

<table align="center">
  <tr>
    <td align="center">
      <p style="font-size: 48px; font-weight: bold; margin: 0;">APIs Workflow</p>
    </td>
  </tr>
</table>

## Signup Process

To sign up a new user, send a POST request to the signup endpoint with the required payload.

**Endpoint:** `{{url}}/auth/signup`

**Payload:**

```json
{
  "email": "md.tarikulislamjuel@gmail.com",
  "password": "12345",
  "firstName": "tarikul",
  "lastName": "juel"
}
```

**Response (Success):**

```json
{
  "success": true,
  "message": "Signup successful and please Verify your user",
  "data": {
    "id": 1,
    "email": "md.tarikulislamjuel@gmail.com",
    "firstName": "tarikul",
    "lastName": "juel"
  }
}
```

After successful signup, an OTP will be sent to the user's email for verification.

## Email(OTP) Verification Process

To verify the user's email, send a POST request to the verification endpoint with the email and OTP.

**Endpoint:** `{{url}}/auth/verify`

**Payload:**

```json
{
  "email": "md.tarikulislamjuel@gmail.com",
  "otp": "503384"
}
```

**Response (Success):**

```json
{
  "success": true,
  "message": "OTP authorised",
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiZW1haWwiOiJtZC50YXJpa3VsaXNsYW1qdWVsQGdtYWlsLmNvbSIsImZpcnN0TmFtZSI6InRhcmlrdWwiLCJsYXN0TmFtZSI6Imp1ZWwiLCJ2ZXJpZmllZCI6ZmFsc2UsImlzRm9yZ2V0UGFzc3dvcmQiOmZhbHNlLCJpYXQiOjE3MTc3Mzg3MTQsImV4cCI6MTcxNzczOTAxNH0.a6QyYCrB6DwV44USECNVpuQsSCyndt04gLyMlVB0vHI",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiZW1haWwiOiJtZC50YXJpa3VsaXNsYW1qdWVsQGdtYWlsLmNvbSIsImZpcnN0TmFtZSI6InRhcmlrdWwiLCJsYXN0TmFtZSI6Imp1ZWwiLCJ2ZXJpZmllZCI6ZmFsc2UsImlzRm9yZ2V0UGFzc3dvcmQiOmZhbHNlLCJpYXQiOjE3MTc3Mzg3MTQsImV4cCI6MTcyMDMzMDcxNH0.FJpya_QRP8lc1YrNpkm9biwQCdLacJ5gt1O3_ewrV0Q",
  "data": {
    "id": 1,
    "email": "md.tarikulislamjuel@gmail.com",
    "firstName": "tarikul",
    "lastName": "juel"
  }
}
```

**Notes:**

- Ensure that the OTP sent to the user is correctly used to authorize the email.
- The access token and refresh token will be provided upon successful verification.

## Signin Process

To sign in a user, send a POST request to the signin endpoint with the required payload.

**Endpoint:** `{{url}}/auth/signin`

**Payload:**

```json
{
  "email": "md.tarikulislamjuel@gmail.com",
  "password": "12345"
}
```

**Response (Success):**

```json
{
  "success": true,
  "message": "Signin successful",
  "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwiZW1haWwiOiJtZC50YXJpa3VsaXNsYW1qdWVsQGdtYWlsLmNvbSIsImZpcnN0TmFtZSI6InRhcmlrdWwiLCJsYXN0TmFtZSI6Imp1ZWwiLCJ2ZXJpZmllZCI6dHJ1ZSwiaXNGb3JnZXRQYXNzd29yZCI6ZmFsc2UsImlhdCI6MTcxNzc0MDUzOSwiZXhwIjoxNzE3NzQwODM5fQ.5a6-DNGrWzepdnxYPuUR_rnEHZadoGBudOjQJwedeVQ",
  "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MiwiZW1haWwiOiJtZC50YXJpa3VsaXNsYW1qdWVsQGdtYWlsLmNvbSIsImZpcnN0TmFtZSI6InRhcmlrdWwiLCJsYXN0TmFtZSI6Imp1ZWwiLCJ2ZXJpZmllZCI6dHJ1ZSwiaXNGb3JnZXRQYXNzd29yZCI6ZmFsc2UsImlhdCI6MTcxNzc0MDUzOSwiZXhwIjoxNzIwMzMyNTM5fQ.8NxRnRQEwDh43dNiWcowxwGm0g0b9cx5LGPoNp4KImk",
  "data": {
    "id": 2,
    "email": "md.tarikulislamjuel@gmail.com",
    "firstName": "tarikul",
    "lastName": "juel"
  }
}
```

**Notes:**

- The access token and refresh token will be provided upon successful signin.

## Resend OTP process:

If the OTP has expired, you can resend it by sending a POST request to the resend endpoint with the user's email.

**Endpoint:** `{{url}}/auth/resend`

**Payload:**

```json
{
  "email": "md.tarikulislamjuel@gmail.com"
}
```

**Response (Success):**

```json
{
  "success": true,
  "message": "OTP email send"
}
```

**Notes:**

- You can then use the **Email Verification process** to verify the email with the new OTP sent.

## Change Password Process

To change a user's password, send a POST request to the change password endpoint with the old and new passwords. This
route is protected by the **JWT Access token**.

**Endpoint:** `{{url}}/auth/change-password`

**Payload:**

```json
{
  "oldPassword": "12345",
  "newPassword": "12345@abcde"
}
```

**Response (Success):**

```json
{
  "success": true,
  "message": "Your password.service.ts has been updated"
}
```

**Notes:**

- This route is protected by the JWT Access token. Ensure that the token is included in the request headers.

## Password Recovery Process

If a user forgets their password, they can initiate a password recovery process. This process involves multiple steps,
starting with requesting an OTP for verification, followed by resetting the password using the provided tokens after
verification.

### Request OTP for Password Recovery

To initiate password recovery, send a POST request to the forget-password endpoint with the user's email.

**Endpoint:** `{{url}}/auth/forget-password`

**Payload:**

```json
{
  "email": "md.tarikulislamjuel@gmail.com"
}
```

**Response (Success):**

```json
{
  "success": true,
  "message": "OTP sent to your email for verification"
}
```

This will trigger an OTP to be sent to the provided email.

### Verify OTP

To verify OTP follow **Email Verification step** and you will get **accessToken**.

### Reset Password

After OTP verification you already received an accessToken. Using this accessToken now follow **Change Password Process
** and the request body will be

```json
{
  "newPassword": "12345"
}
```

here you dont need to use oldPassword field.

## 🔐 Password Validation Configuration

Easily customize password validation rules for your application using the environment variables in the `.env` file. This
allows you to enforce specific security requirements based on your project's needs.

### Configuration Options:

- **`PASSWORD_MIN_LENGTH`**: Sets the minimum password length (e.g., `8`).
- **`PASSWORD_MAX_LENGTH`**: Sets the maximum password length (e.g., `20`).
- **`PASSWORD_REQUIRE_UPPERCASE`**: Requires at least one uppercase letter (`true` or `false`).
- **`PASSWORD_REQUIRE_LOWERCASE`**: Requires at least one lowercase letter (`true` or `false`).
- **`PASSWORD_REQUIRE_NUMBERS`**: Requires at least one numeric digit (`true` or `false`).
- **`PASSWORD_REQUIRE_SPECIAL_CHARACTERS`**: Requires at least one special character (e.g., `!@#$%`) (`true` or
  `false`).
- **`PASSWORD_DISALLOW_REPEATING`**: Prevents the use of consecutive repeating characters (`true` or `false`).
- **`PASSWORD_DISALLOW_SEQUENTIAL`**: Prevents the use of sequential characters (e.g., `123`, `abc`) (`true` or
  `false`).
- **`PASSWORD_BLACKLIST_COMMON`**: Blocks common passwords like `password`, `123456` (`true` or `false`).
- **`PASSWORD_EXCLUDE_USERNAME`**: Ensures the password does not contain the username (`true` or `false`).

### Example Configuration:

Modify the following variables in your `.env` file to define your desired password policy:

```bash
PASSWORD_MIN_LENGTH=10
PASSWORD_MAX_LENGTH=20
PASSWORD_REQUIRE_UPPERCASE=true
PASSWORD_REQUIRE_LOWERCASE=true
PASSWORD_REQUIRE_NUMBERS=true
PASSWORD_REQUIRE_SPECIAL_CHARACTERS=true
PASSWORD_DISALLOW_REPEATING=false
PASSWORD_DISALLOW_SEQUENTIAL=false
PASSWORD_BLACKLIST_COMMON=true
PASSWORD_EXCLUDE_USERNAME=true
```

## 🔐 Multi-Factor Authentication (MFA) Support

This **NestJS Authentication Boilerplate** includes support for **Multi-Factor Authentication (MFA)** using email. When
MFA is enabled, after entering the correct credentials, users will receive a **One-Time Password (OTP)** via email to
complete the login process.

- **MFA Enabled**: Users receive an OTP after signing in, required to finalize the authentication.
- **Customizable**: MFA is optional and can be enabled or disabled for each user.
- **Lockout Protection**: After a set number of failed OTP attempts, the account will be temporarily locked for enhanced
  security.
- **Environment Control**: You can configure the following settings via the `.env` file:
  - `OTP_EXPIRE_TIME`: Time (in minutes) before the OTP expires. Default is 5 minutes.
  - `OTP_MAX_FAILED_ATTEMPTS`: Maximum number of allowed failed OTP attempts before account lockout. Default is 5
    attempts.
  - `OTP_LOCKOUT_TIME`: Time (in minutes) for which the account will be locked after exceeding the maximum failed OTP
    attempts. Default is 5 minutes.

MFA adds an extra layer of security by ensuring that even if a user's password is compromised, unauthorized access to
the account is still prevented.


## 📦 Dockerize Your NestJS Application for Production

For detailed instructions on how to Dockerize your NestJS application for production, refer to this comprehensive guide:

check it

[Building and Deploying a NestJS Application with Docker Compose, PostgreSQL, and Prisma](https://medium.com/@md.tarikulislamjuel/building-and-deploying-a-nestjs-application-with-docker-compose-postgresql-and-prisma-659ba65da25b "Building and Deploying a NestJS Application with Docker Compose, PostgreSQL, and Prisma")



## 📞 Contact Information

For any inquiries or further assistance, feel free to reach out:

- **Email:** [md.tarikulislamjuel@gmail.com](mailto:md.tarikulislamjuel@gmail.com)
- **LinkedIn:** [Tarikul Islam Juel](https://www.linkedin.com/in/tarikulislamjuel/)

<p align="center">
  <a href="mailto:md.tarikulislamjuel@gmail.com"><img src="https://img.icons8.com/color/48/000000/gmail.png" alt="Gmail" style="margin: 0 15px;"/></a>
  <a href="https://www.linkedin.com/in/tarikulislamjuel/"><img src="https://img.icons8.com/color/48/000000/linkedin.png" alt="LinkedIn" style="margin: 0 15px;"/></a>
</p>
