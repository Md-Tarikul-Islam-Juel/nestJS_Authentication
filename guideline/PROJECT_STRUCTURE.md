# Project Structure

## Clean Architecture Principles

This project follows **Clean Architecture** with strict layer separation:

### Dependency Rule

- **Application Layer** depends on **Domain Layer** (ports/interfaces)
- **Infrastructure Layer** implements **Domain Layer** ports (adapters)
- **Domain Layer** has NO dependencies on other layers (pure business logic)
- **Interface Layer** depends on **Application Layer** (use-cases only)

### Ports & Adapters Pattern

All infrastructure dependencies are abstracted through **Ports** (interfaces) in the domain layer:

- **Ports** (`domain/repositories/*.port.ts`) - Define contracts in domain layer
- **Adapters** (`infrastructure/*/`) - Implement ports in infrastructure layer
- **DI Tokens** (`application/di-tokens.ts`) - Bind ports to adapters via dependency injection

### Example: Auth Module Ports & Adapters

| Port (Domain)        | Adapter (Infrastructure) | Purpose                   |
| -------------------- | ------------------------ | ------------------------- |
| `UserRepositoryPort` | `UserPrismaRepository`   | User persistence          |
| `EmailServicePort`   | `EmailService`           | Email sending             |
| `OtpCachePort`       | `OtpCache`               | OTP caching (Redis)       |
| `ActivityCachePort`  | `ActivityCache`          | Activity tracking (Redis) |
| `JwtServicePort`     | `JwtAdapter`             | JWT token generation      |
| `LoggerPort`         | `LoggerAdapter`          | Application logging       |
| `UnitOfWorkPort`     | `PrismaUnitOfWork`       | Transaction management    |

### Allowed Dependencies

✅ **Application Layer** can depend on:

- Domain ports/interfaces
- Domain entities, value objects, errors, enums

❌ **Application Layer** MUST NOT depend on:

- Infrastructure implementations directly
- Platform services directly (use ports instead)

```
apps/api/src/
├─ main.ts                                  # Bootstrap: DI container, global middlewares/filters/pipes (HTTP + GraphQL share req-id, etc.)
├─ app.module.ts                            # Root module (non-HTTP runtime entry; wires cross-cutting modules)
├─ app-http.module.ts                       # HTTP composition root (controllers, filters, interceptors, versioning)
├─ app-graphql.module.ts                    # ✨ GraphQL composition root (ApolloDriver config, context, plugins, depth/complexity, uploads)

├─ config/                                   # Typed config, env validation, DI tokens (DIP)
│  ├─ config.module.ts                       # Loads/validates env; exposes ConfigService globally
│  ├─ env.schema.ts                         # class-validator schema for process.env
│  ├─ tokens.ts                             # IoC tokens (ports/adapters, buses, stores)
│  ├─ defaults.ts                           # Sensible defaults (timeouts, limits, pagination caps)
│  └─ feature-flags.ts                       # Typed feature flag port (DIP) used by app layers

├─ common/                                  # Cross-cutting concerns (reused everywhere)
│  ├─ http/
│  │  ├─ filters/
│  │  │  └─ problem-details.filter.ts        # RFC7807 mapper (HTTP only; GraphQL uses gql-exception.filter)
│  │  ├─ interceptors/
│  │  │  ├─ logging.interceptor.ts          # Structured request logs (method, path, latency, reqId)
│  │  │  ├─ timeout.interceptor.ts          # Request timeout guardrail
│  │  │  ├─ etag.interceptor.ts             # ETag / If-None-Match support for safe GETs
│  │  │  └─ cache.interceptor.ts            # Cache-Control + server-side caching where applicable
│  │  ├─ guards/                            # HTTP guards (RBAC/ABAC), auth checks
│  │  ├─ pipes/
│  │  │  └─ validation.pipe.ts              # Global ValidationPipe config (whitelist, transform, forbid*)
│  │  └─ versioning.ts                      # /api/v1 versioning helpers + deprecation headers
│  ├─ graphql/                              # ✨ GraphQL cross-cutting (framework-agnostic where possible)
│  │  ├─ scalars/
│  │  │  ├─ date-time.scalar.ts             # ISO-8601 DateTime scalar
│  │  │  ├─ uuid.scalar.ts                  # UUID scalar (validates format)
│  │  │  └─ decimal.scalar.ts               # Decimal scalar (string transport to avoid float issues)
│  │  ├─ directives/
│  │  │  ├─ auth.directive.ts               # @auth(role: ...): delegates to policy/guard (DIP-compliant)
│  │  │  └─ upper-case.directive.ts         # Example SDL directive (presentation concern)
│  │  ├─ plugins/
│  │  │  └─ logging.plugin.ts               # Apollo plugin: op name, timing, errors -> structured logs
│  │  ├─ guards/
│  │  │  └─ gql-policy.guard.ts             # GraphQL guard: RBAC/ABAC using policies + context user
│  │  ├─ loaders/
│  │  │  └─ dataloader.factory.ts           # Per-request DataLoader registry (prevents N+1)
│  │  ├─ errors/
│  │  │  └─ gql-exception.filter.ts         # Maps domain/application errors → safe GraphQL errors (no internals)
│  │  ├─ complexity/
│  │  │  └─ complexity.factory.ts           # Query depth/cost limits + persisted queries toggle
│  │  └─ schema/
│  │     └─ naming.ts                       # Helpers: PascalCase types, camelCase fields, deprecations
│  ├─ security/
│  │  ├─ helmet.ts                          # Secure headers for HTTP endpoints
│  │  ├─ rate-limiter.ts                    # Throttling config (HTTP; GraphQL rate-limit at gateway or plugin)
│  │  ├─ cors.ts                            # CORS allowlist; no * in prod
│  │  └─ body-size.ts                       # Request size limits (uploads)
│  ├─ observability/
│  │  ├─ request-id.middleware.ts           # X-Request-Id correlation (propagate into GQL context)
│  │  ├─ otel.ts                            # OpenTelemetry bootstrap (Nest, HTTP, Prisma, outbound HTTP)
│  │  └─ audit-logger.ts                    # Domain/audit logging helper (sensitive ops)
│  ├─ errors/
│  │  ├─ domain-error.ts                    # Base domain error (no transport coupling)
│  │  ├─ error-codes.ts                     # Uniform error codes (stable identifiers)
│  │  ├─ concurrency.ts                     # ETag/If-Match helpers (412) for HTTP resources
│  │  └─ problem.ts                         # RFC7807 factory + serializers (HTTP transport)
│  ├─ messaging/
│  │  ├─ event-bus.port.ts                  # Domain event bus port (DIP)
│  │  ├─ command-bus.port.ts                # Optional CQRS command bus port
│  │  └─ outbox.port.ts                     # Transactional outbox port
│  ├─ persistence/
│  │  ├─ pagination.ts                      # Offset/cursor helpers (sort keys, nextCursor)
│  │  └─ uow/                               # Shared Unit-of-Work port + tokens (used across modules)
│  │     ├─ di-tokens.ts
│  │     └─ uow.port.ts
│  ├─ idempotency/
│  │  ├─ key.interceptor.ts                 # Idempotency-Key enforcement for critical POST
│  │  └─ store.port.ts                      # Idempotency store port (e.g., Redis)
│  ├─ auth/
│  │  ├─ strategies/                        # Cross-cutting auth guards (JWT, OAuth, etc.)
│  │  │  ├─ access-token.strategy.ts         # Access token guard (HTTP + GraphQL)
│  │  │  ├─ refresh-token.strategy.ts        # Refresh token guard with logout validation
│  │  │  └─ logout-token-validate.service.ts  # Token revocation validation
│  │  └─ guards/                            # Additional auth guards as needed
│  ├─ authz/
│  │  ├─ policies/                          # Policy rules (ABAC/RBAC)
│  │  └─ policy.decorator.ts                # @Policy() decorator for controllers/resolvers
│  ├─ i18n/                                 # Optional localization helpers
│  └─ util/                                 # Pure helpers (DRY, KISS)

├─ modules/                                      # All bounded contexts (DDD modules)
│
│  ├─ _shared/                                   # Shared utilities across modules (NOT business logic)
│  │  ├─ query-spec.ts                           # Query specification (filter, sort, paging rules)
│  │  └─ constants.ts                            # Constants reused inside modules (no global app stuff)
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
│  │  │  ├─ repositories/                        # Repository PORTS (interfaces — no implementation here)
│  │  │  │  ├─ user.repository.port.ts           # User repository port (implements in infrastructure)
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
│  │  │  ├─ services/                            # Application Services (business logic, utilities, helpers)
│  │  │  │  ├─ auth.service.ts                   # Main application service (orchestrates use-cases)
│  │  │  │  ├─ common-auth.service.ts            # Common auth utilities (data sanitization, token sanitization)
│  │  │  │  ├─ user.service.ts                   # User operations service
│  │  │  │  ├─ otp.service.ts                    # OTP operations service
│  │  │  │  ├─ otp-domain.service.ts             # OTP generation domain service
│  │  │  │  ├─ password-policy.service.ts        # Password hashing service
│  │  │  │  ├─ password-validation.service.ts    # Password validation business logic (includes config)
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
│  │  │  ├─ use-cases/                           # Application use-cases (orchestrate commands & domain logic)
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
│  │  │  ├─ uow/                                 # Prisma Unit-of-Work implementation ($transaction)
│  │  │  │  └─ prisma.uow.ts
│  │  │  ├─ cache/                               # Cache adapters (Redis implementations)
│  │  │  │  ├─ otp.cache.ts                      # OTP cache adapter (implements OtpCachePort)
│  │  │  │  └─ activity.cache.ts                 # Activity cache adapter (implements ActivityCachePort)
│  │  │  ├─ oauth-strategies/                    # OAuth provider strategies (Facebook, Google, etc.)
│  │  │  │  ├─ facebook.strategy.ts              # Passport Facebook strategy
│  │  │  │  └─ google.strategy.ts                # Passport Google strategy
│  │  │  ├─ email/                               # Email service adapters
│  │  │  │  └─ email.service.ts                  # Email service adapter (implements EmailServicePort)
│  │  │  ├─ jwt/                                 # JWT service adapters
│  │  │  │  └─ jwt.adapter.ts                    # JWT adapter (implements JwtServicePort)
│  │  │  ├─ observability/                       # Observability adapters
│  │  │  │  └─ logger.adapter.ts                 # Logger adapter (implements LoggerPort)
│  │  │  └─ outbox/                              # Transactional outbox for event-driven consistency
│  │
│  │  └─ interface/                              # Delivery Layer (No business logic)
│  │     ├─ http/                                # REST API Adapters (Controllers)
│  │     │  ├─ auth.controller.ts                # HTTP endpoints → call use-cases only (thin layer)
│  │     │  └─ interceptors/                     # HTTP interceptors
│  │     │     └─ track-last-activity.interceptor.ts
│  │     ├─ graphql/                             # GraphQL API Adapters (Resolvers) - Future
│  │     ├─ validators/                          # Framework adapters (class-validator decorators)
│  │     │  ├─ password-validator.class.ts       # Thin adapter delegating to PasswordValidationService
│  │     │  └─ password-decorator.decorator.ts   # Decorator factory for @PasswordValidation()
│  │
│  ├─ users/                                     # Bounded Context: Users Domain (Example structure)
│  │  ├─ domain/
│  │  ├─ application/
│  │  ├─ infrastructure/
│  │  └─ interface/

├─ health/
│  └─ health.controller.ts                  # /health /ready /live probes (HTTP)

└─ platform/                                # Concrete infrastructure wiring
   ├─ prisma/
   │  ├─ prisma.module.ts                   # Registers Prisma + repository bindings
   │  └─ prisma.client.ts                   # Prisma Client instance
   ├─ jwt/                                  # JWT token infrastructure
   │  ├─ jwt.module.ts                      # JWT module configuration
   │  └─ jwt.service.ts                     # Token generation/validation service
   ├─ redis/                                # Redis client module
   ├─ queue/                                # BullMQ / Temporal / SQS workers
   ├─ storage/                              # S3/GCS file storage adapter
   └─ http-client/                          # Axios/fetch adapter module
```
