# Threat Model - Authentication System

## Assets
1. User credentials (passwords, tokens)
2. User personal data (email, name)
3. Session data (JWTs, refresh tokens)
4. OAuth tokens (Google, Facebook)

## Threat Actors
1. External attackers
2. Malicious users
3. Compromised accounts

## Attack Vectors

### 1. Brute Force Attacks
**Mitigation:**
- Rate limiting (100 req/min)
- Account lockout after failed attempts
- CAPTCHA (future)

### 2. Credential Stuffing
**Mitigation:**
- Password strength requirements
- MFA/OTP support
- Anomaly detection

### 3. Session Hijacking
**Mitigation:**
- JWE encryption
- Token rotation
- Device fingerprinting

### 4. CSRF Attacks
**Mitigation:**
- CSRF tokens
- SameSite cookies
- Double-submit pattern

### 5. SQL Injection
**Mitigation:**
- Prisma ORM
- Parameterized queries
- Input validation

### 6. XSS Attacks
**Mitigation:**
- Input sanitization
- Content Security Policy
- Output encoding

### 7. DDoS Attacks
**Mitigation:**
- DDoS protection guard
- Rate limiting
- IP blocking

### 8. Geolocation Bypass
**Mitigation:**
- IP-based geolocation
- VPN detection (future)
- Multiple verification methods
