# Error Handling

## ⚙️ Error Handling (NestJS Standard)

**Domain Exceptions inside Services** →  
Throw custom domain errors (e.g., EmailAlreadyTakenError) for business rule violations.  
(Keywords: domain-driven design, invariant enforcement, rollback trigger, testability, clean logic).

**Global Exception Filter** →  
Catch all errors centrally and convert them into standard HTTP responses.  
(Keywords: centralized handling, consistency, separation of concerns, maintainability).

**RFC 7807 (HTTP Problem Details)** →  
Use structured JSON for all 4xx/5xx responses —  
type, title, status, detail, instance, code, traceId.  
(Keywords: interoperability, observability, debuggability, predictable contract).

**Domain → HTTP Mapping** →  
Map domain errors to proper HTTP codes in one place (400, 403, 404, 409, etc.).  
(Keywords: translation layer, uniform response, stability).

---

## ✅ Essence:

Throw domain exceptions → handled globally → returned as RFC 7807 Problem Details → mapped centrally to HTTP codes.
