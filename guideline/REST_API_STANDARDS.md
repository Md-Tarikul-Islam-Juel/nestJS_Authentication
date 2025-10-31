# REST API Standards

## 🧱 Resources & URIs

Nouns, plural, shallow: /users, /users/{id}, /orders/{id}/items  
No verbs/actions in paths → /sessions ✅ /login ❌  
Stable IDs → uuid, snowflake, opaque  
kebab-case paths, RESTful, HATEOAS-friendly

---

## ⚙️ HTTP Methods & Idempotency

GET = read, POST = create, PUT = replace, PATCH = partial, DELETE = remove  
Idempotent → PUT, DELETE  
Idempotency-Key header for critical POST (payments, retries, dedupe)

---

## 🧭 Versioning

URI versioning → /api/v1/...  
SemVer = MAJOR (breaking) / MINOR (additive) / PATCH (fix)  
Headers → Sunset, Deprecation, Link

---

## 🔍 Query / Pagination / Filtering / Search

**Offset Pagination** → ?page=1&limit=20 (simple, default pattern)  
**Cursor Pagination** → ?cursor=eyJpZCI6Ij...&limit=20 (scalable, real-time safe)  
**Sort** → ?sort=createdAt:desc (multi-field allowed — e.g., ?sort=createdAt:desc,name:asc)  
**Filter** → ?filter[status]=active&filter[ownerId]=123 (structured filters, whitelist fields)  
**Sparse Fields** → ?fields=id,name,email (projection for lightweight responses)  
**Search (Full-Text / Keyword)** →

- Basic: ?q=adnan islam (free-text, ranked relevance)
- Fielded: ?search[name]=adnan&search[email]=@citybank.com (targeted fields)
- Advanced operators: ?q="invoice july" -draft status:active created:>=2025-01-01 (GitHub-style query DSL)

**Response Meta (recommended)** → include total, page, limit, nextCursor, sort, filters, q.

---

## 📡 Status Codes

**200 OK** → Standard success response for GET, PUT, PATCH, and DELETE.

**201 Created** → Resource successfully created (include Location header).

**202 Accepted** → Request accepted for asynchronous or background processing.

**204 No Content** → Request processed successfully, no response body (e.g., DELETE).

**304 Not Modified** → Cached resource still valid (ETag / If-None-Match support).

**400 Bad Request** → Invalid parameters, missing fields, or malformed request.

**401 Unauthorized** → Missing or invalid authentication credentials.

**403 Forbidden** → Authenticated user lacks required permissions.

**404 Not Found** → Requested resource not found or intentionally hidden.

**409 Conflict** → Request conflicts with existing resource state (duplicate, version mismatch, idempotency conflict).

**412 Precondition Failed** → Failed ETag / If-Match condition (concurrency control).

**415 Unsupported Media Type** → Unsupported Content-Type (expect application/json).

**422 Unprocessable Entity** → Request valid syntactically but violates business or domain rules.

**429 Too Many Requests** → Rate limit exceeded (include Retry-After header).

**500 Internal Server Error** → Unexpected server-side failure (log, include trace ID).

**503 Service Unavailable** → Temporary outage or maintenance mode (use Retry-After header).

---

## 🧰 Headers & Caching

Cache-Control  
Compression → Content-Encoding: gzip/br (HTTP/2, HTTP/3)

---

## 🧾 Request / Response

JSON default (application/json; UTF-8)  
ISO-8601 UTC timestamps (2025-10-30T11:22:33Z)  
Stable schema, explicit types, no polymorphic leaks  
DTO mapping — never expose ORM entities

---

## ❗ Errors

RFC 7807 Problem Details:  
{ type, title, status, detail, instance, code, errors }  
Validation → 400/422 with per-field messages  
Consistent • Debuggable • Human-Readable

---

## 🔒 Security

HTTPS only, HSTS, no mixed content  
AuthN: OAuth2 / OIDC / JWT (short TTL + rotation + kid)  
AuthZ: Scopes / Roles / RBAC / ABAC  
Input validation, sanitization, size limits, allowlists  
CORS: Allowlist origins, no \* in prod  
Rate-limit (429 + Retry-After), bot protection  
Secrets → hashed (Argon2/bcrypt), encrypted (KMS/Vault)

---

## 🧩 Reliability & Resilience

Timeouts, Retries (Exponential Backoff + Jitter)  
Circuit Breaker, Bulkhead, Dead Letter Queue  
Long-running → 202 Accepted + status endpoint or webhook

---

## 🔭 Observability

Correlation ID (X-Request-Id)  
Structured Logs (JSON), Metrics (RED/USE), Tracing (OpenTelemetry)  
Audit Logs for sensitive actions

---

## 📘 Documentation & Tooling

OpenAPI 3.x, examples, enums, strict schema  
Postman / curl / HTTPie examples | SDK (codegen)  
Changelog, Deprecation Timeline, Migration Guide

---

## ⚡ Performance

Avoid N+1, batching, expand/include safe  
Pagination mandatory, no unbounded lists  
HTTP/2 or 3, Keep-Alive, Compression  
Cache (client + edge + server) → stale-while-revalidate

---

## 📬 Webhooks & Uploads

**Webhooks:** Signed (HMAC), Retries + Backoff, Idempotent, Versioned  
**Uploads:** Pre-signed URL (S3/GCS), MIME + Magic-byte check, Virus scan, Size limit, Checksum (md5/sha256)

---

## 🧩 Consistency & Governance

Naming: kebab-case paths / camelCase fields  
Uniform codes & errors, shared libs  
Backward compatibility within MAJOR, additive only  
CI Gates: OpenAPI lint / contract test / Spectral / Schemathesis
