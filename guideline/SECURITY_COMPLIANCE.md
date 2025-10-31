# Security & Compliance

## 🔒 Security & Compliance (Industry Standard)

**HTTP Hardening** →  
Use Helmet for secure headers (X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Strict-Transport-Security).  
(Keywords: clickjacking, MIME sniffing, CSP, HSTS, secure headers, SSRF prevention, HTTPS-only).

**Rate Limiting & Throttling** →  
Prevent abuse and DoS with @nestjs/throttler or reverse proxy rate limits.  
(Keywords: brute-force protection, 429 Too Many Requests, Retry-After, DoS mitigation, fairness control).

**Input Validation & Sanitization** →  
Enforce schema validation using class-validator + Pipes.  
(Keywords: injection prevention, XSS mitigation, whitelist mode, strict typing, data integrity).

**Secrets Management** →  
Never hardcode secrets; load from ConfigService, environment, or Vault/KMS.  
(Keywords: 12-Factor App, key rotation, secret lifecycle, least privilege, .env hygiene, encryption-at-rest).

**Audit Logging & Monitoring** →  
Log all sensitive actions (login, access, config change, admin ops) with correlation IDs.  
(Keywords: non-repudiation, traceability, forensics, compliance, SIEM integration).

**Authentication & MFA** →  
Support JWT/OAuth2/OIDC, short TTL tokens, refresh rotation, and optional MFA/2FA.  
(Keywords: PKCE, secure cookie, HttpOnly, SameSite, bearer token, session integrity).

**Authorization & Access Control** →  
Implement RBAC, ABAC, or policy-based controls per resource/action.  
(Keywords: least privilege, role hierarchy, scope-based access, context-aware policies).

**OWASP ASVS Alignment** →  
Follow OWASP Application Security Verification Standard (ASVS v4.0) and OWASP API Security Top 10.  
(Keywords: A01 Broken Object Level Auth, A05 Security Misconfiguration, A07 Injection, A09 Improper Assets Mgmt).

**Data Protection** →

- TLS 1.2+ (HTTPS only)
- Encrypt sensitive data (AES-256, RSA, bcrypt/argon2 for passwords)
- Mask PII in logs and payloads

(Keywords: encryption-at-rest, encryption-in-transit, data minimization, GDPR compliance).

**Compliance & Governance** →  
Align with ISO 27001, SOC 2, PCI DSS, GDPR, and NIST CSF frameworks.  
(Keywords: risk management, audit readiness, data classification, retention policy, least privilege).

---

## ✅ Core Keywords Summary:

Helmet • Rate Limiting • Validation Pipe • Secrets Management • Audit Logs • MFA/2FA • RBAC/ABAC • OWASP ASVS • OWASP API Top 10 • TLS 1.2+ • Encryption • GDPR • SOC 2 • ISO 27001 • PCI DSS • NIST CSF • Least Privilege • Compliance • Secure Headers • Logging • Monitoring • SIEM.
