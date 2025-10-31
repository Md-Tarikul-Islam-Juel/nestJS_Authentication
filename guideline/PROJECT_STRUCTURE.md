# Project Structure

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
│  │  └─ pagination.ts                      # Offset/cursor helpers (sort keys, nextCursor)
│  ├─ idempotency/
│  │  ├─ key.interceptor.ts                 # Idempotency-Key enforcement for critical POST
│  │  └─ store.port.ts                      # Idempotency store port (e.g., Redis)
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
│  ├─ users/                                     # Bounded Context: Users Domain
│  │
│  │  ├─ domain/                                 # PURE Domain Layer (no NestJS, no Prisma, no HTTP)
│  │  │  ├─ entities/                            # Domain Entities → define state + invariants
│  │  │  │  └─ user.entity.ts
│  │  │  ├─ value-objects/                       # Immutable value objects (Email, Password, Name, etc.)
│  │  │  │  ├─ email.vo.ts
│  │  │  │  └─ password.vo.ts
│  │  │  ├─ services/                            # Domain Services (business rules, policies)
│  │  │  │  └─ user-domain.service.ts
│  │  │  ├─ events/                              # Domain events (past-tense: UserRegistered)
│  │  │  │  └─ user-registered.event.ts
│  │  │  ├─ repositories/                        # Repository PORTS (interfaces — no implementation here)
│  │  │  │  └─ user.repository.port.ts
│  │  │  └─ errors/                              # Domain-specific exceptions (business rule violations)
│  │  │     └─ email-already-exists.error.ts
│  │
│  │  ├─ application/                            # Application Layer (Use-Cases) — Orchestrates domain
│  │  │  ├─ dto/                                 # Input DTOs (validated in interface layer before use)
│  │  │  │  ├─ create-user.dto.ts
│  │  │  │  └─ user.dto.ts
│  │  │  ├─ commands/                            # Write-side operations (state-changing)
│  │  │  │  └─ create-user.command.ts
│  │  │  ├─ queries/                             # Read-side operations (no state change)
│  │  │  │  └─ get-user.query.ts
│  │  │  ├─ handlers/                            # Execution logic for commands & queries
│  │  │  │  ├─ create-user.handler.ts
│  │  │  │  └─ get-user.handler.ts
│  │  │  ├─ mappers/                             # Domain ↔ DTO/View mapping (no ORM, pure mapping)
│  │  │  │  └─ user.mapper.ts
│  │  │  └─ uow/                                 # Unit-of-Work Port → abstracts db transaction boundary
│  │  │     └─ uow.port.ts
│  │
│  │  ├─ infrastructure/                         # Infrastructure Layer (Adapters to technologies)
│  │  │  ├─ prisma/                              # Prisma persistence layer implementations
│  │  │  │  ├─ user.prisma.mapper.ts             # Maps Prisma models ↔ Domain Entities
│  │  │  │  └─ user.prisma.repository.ts         # Repository adapter (implements repository.port)
│  │  │  ├─ uow/                                 # Prisma Unit-of-Work implementation ($transaction)
│  │  │  │  └─ prisma.uow.ts
│  │  │  ├─ cache/                               # Optional cache adapters (Redis, Memory, etc.)
│  │  │  │  └─ user.cache.ts
│  │  │  └─ outbox/                              # Transactional outbox for event-driven consistency
│  │  │     └─ user-outbox.publisher.ts
│  │
│  │  └─ interface/                              # Delivery Layer (No business logic)
│  │     ├─ http/                                # REST API Adapters (Controllers)
│  │     │  ├─ users.controller.ts               # HTTP endpoints → call use-cases only (thin layer)
│  │     │  └─ users.presenter.ts                # Shapes HTTP response (pagination, envelope responses)
│  │     ├─ graphql/                             # GraphQL API Adapters (Resolvers)
│  │     │  ├─ users.resolver.ts                 # Query/Mutation resolvers → call use-cases only
│  │     │  ├─ users.inputs.ts                   # @InputType DTOs for GraphQL mutations
│  │     │  ├─ users.types.ts                    # @ObjectType output models for GraphQL
│  │     │  ├─ users.dataloaders.ts              # DataLoader to avoid N+1 queries (per-request scoped)
│  │     │  └─ users.schema.gql                  # (Optional) SDL if mixing schema-first
│  │     ├─ validators/                          # class-validator pipes (used in HTTP layer)
│  │     │  └─ create-user.schema.ts
│  │     └─ presenters/                          # Shared view helpers (used by REST & GraphQL)
│  │        └─ user.presenter.ts

├─ health/
│  └─ health.controller.ts                  # /health /ready /live probes (HTTP)

└─ platform/                                # Concrete infrastructure wiring
   ├─ prisma/
   │  ├─ prisma.module.ts                   # Registers Prisma + repository bindings
   │  └─ prisma.client.ts                   # Prisma Client instance
   ├─ redis/                                # Redis client module
   ├─ queue/                                # BullMQ / Temporal / SQS workers
   ├─ storage/                              # S3/GCS file storage adapter
   └─ http-client/                          # Axios/fetch adapter module
```
