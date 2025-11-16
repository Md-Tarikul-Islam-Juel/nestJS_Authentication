## JTI-based Refresh Token Rotation (Project Implementation Guide)

This document explains how JTI (JWT ID) works in this project: how it is generated, stored, validated, rotated, and how to configure it.

### Key terms

- sid: Session ID for a single device/session (e.g., phone-1). Used to scope refresh validation per device.
- jti: Unique ID of a refresh token. Rotated on every successful refresh; only the current jti per sid is valid.
- Allowlist: Server-side record of the one valid jti for a given sid stored in Redis with a TTL equal to refresh expiry.

### Redis keys summary

- Per-session allowlist:
  - key: `auth:session:<sid>:jti`
  - value: `<current_jti>`
  - ttl: equals refresh token expiration (e.g., 7d)
- Per-user session index:
  - key: `auth:user:<userId>:session:<sid>`
  - value: `1`
  - ttl: equals refresh token expiration

### What is JTI?

- jti = JWT ID (a unique identifier for a specific JWT).
- We attach a `jti` to every refresh token and track the current, valid `jti` per session in Redis.
- Outcome: single-use refresh tokens, reuse detection, and instant session revocation.

### End-to-end Flow

1. Sign-in

- Authenticate user.
- Generate `sid` and `jti`.
- Save `jti` to Redis under the session key with TTL = refresh expiry.
- Issue access token and refresh token containing `sid` and `jti`.

Example:

```text
User: alice@example.com (id=42) signs in successfully

1) Generate identifiers
   sid = "sid_8f0c4a8e-3a7a-44a0-8e92-0d4f11b7e5d0"    # session ID (UUID v4 with prefix)
   jti = "d1c1b7b4-9f9e-4f9a-9a2b-2f4a6a0e3c71"        # refresh token JTI (UUID v4)

2) Store allowlisted jti in Redis with TTL = refresh expiration (e.g., 7 days)
   - key:   auth:session:sid_8f0c4a8e-3a7a-44a0-8e92-0d4f11b7e5d0:jti
     value: d1c1b7b4-9f9e-4f9a-9a2b-2f4a6a0e3c71
     ttl:   7d
     note:  current (single valid) jti for this session; must match refresh token’s jti
   - key:   auth:user:42:session:sid_8f0c4a8e-3a7a-44a0-8e92-0d4f11b7e5d0
     value: 1
     ttl:   7d
     note:  index entry so we can find all sessions for user 42 (used for logout-all)

3) Issue tokens that embed sid/jti in the refresh token payload
   refreshToken.payload = {
     "id": 42,
     "email": "alice@example.com",
     "sid": "sid_8f0c4a8e-3a7a-44a0-8e92-0d4f11b7e5d0",
     "jti": "d1c1b7b4-9f9e-4f9a-9a2b-2f4a6a0e3c71",
     "iat": 1731770000,
     "exp": 1732374800
   }

Result: The client now holds a refresh token tied to (sid, jti). Only the jti currently stored for that sid will be accepted on the next refresh.
```

Redis entries explained:

```text
auth:session:<sid>:jti
  - Stores the only accepted jti for that <sid>.
  - On refresh: server checks equality, then rotates to a new jti and resets TTL.

auth:user:<userId>:session:<sid>
  - Simple index: marks that <sid> belongs to <userId>.
  - On logout-all: server lists these keys for the user, deletes each auth:session:<sid>:jti, then removes the index keys.
```

### Real-life scenario (simple values)

User: alice@example.com (userId = 42) uses two devices.

1. Phone login

- Server creates:
  - sid_phone_1
  - jti_phone_1
- Redis:
  - auth:session:sid_phone_1:jti → jti_phone_1 (EX=7d)
  - auth:user:42:session:sid_phone_1 → 1 (EX=7d)
- Phone’s refresh token payload: sid = "sid_phone_1", jti = "jti_phone_1".

2. Laptop login

- Server creates:
  - sid_laptop_1
  - jti_laptop_1
- Redis:
  - auth:session:sid_laptop_1:jti → jti_laptop_1 (EX=7d)
  - auth:user:42:session:sid_laptop_1 → 1 (EX=7d)
- Laptop’s refresh token payload: sid = "sid_laptop_1", jti = "jti_laptop_1".

3. Phone refresh (rotation)

- Phone calls POST /auth/refresh-token with jti = "jti_phone_1".
- Server checks Redis: auth:session:sid_phone_1:jti == jti_phone_1 → OK.
- Server rotates:
  - new jti_phone_2
  - Redis: auth:session:sid_phone_1:jti → jti_phone_2 (EX reset to 7d)
- New refresh token payload(phone): sid = "sid_phone_1", jti = "jti_phone_2".

4. Old token reuse (blocked)

- Attacker uses old phone refresh (jti = "jti_phone_1").
- Redis has jti_phone_2 → mismatch → 401 Unauthorized.

5. Logout-all

- Server enumerates:
  - auth:user:42:session:sid_phone_1
  - auth:user:42:session:sid_laptop_1
- For each sid:
  - delete auth:session:<sid>:jti
  - delete auth:user:42:session:<sid>
- Result: all refresh tokens fail on next use; access tokens expire naturally.

### Multi-device scenario (phone-1, phone-2, laptop-1)

Goal: Show why both Redis keys exist and how device-specific refresh vs logout-all behave.

1. Logins (three devices)

- phone-1 signs in
  - auth:session:sid_phone_1:jti → jti_phone_1 (EX=7d)
  - auth:user:42:session:sid_phone_1 → 1 (EX=7d)
- phone-2 signs in
  - auth:session:sid_phone_2:jti → jti_phone_2 (EX=7d)
  - auth:user:42:session:sid_phone_2 → 1 (EX=7d)
- laptop-1 signs in
  - auth:session:sid_laptop_1:jti → jti_laptop_1 (EX=7d)
  - auth:user:42:session:sid_laptop_1 → 1 (EX=7d)

2. phone-1 refreshes (device-specific rotation)

- Client sends refresh (sid = sid_phone_1, jti = jti_phone_1)
- Server validates equality: auth:session:sid_phone_1:jti == jti_phone_1 → OK
- Server rotates only phone-1:
  - auth:session:sid_phone_1:jti → jti_phone_1_v2 (EX reset to 7d)
- Impact on others:
  - phone-2 still has jti_phone_2 → unaffected
  - laptop-1 still has jti_laptop_1 → unaffected

3. Reuse attack: old phone-1 token

- Attacker uses old jti_phone_1
- Server compares with Redis (now jti_phone_1_v2) → mismatch → 401 Unauthorized
- phone-2 and laptop-1 continue to work normally

4. Logout-all (requires both key types)

- Server enumerates user sessions using index keys:
  - auth:user:42:session:sid_phone_1
  - auth:user:42:session:sid_phone_2
  - auth:user:42:session:sid_laptop_1
- For each sid, server deletes both:
  - auth:session:<sid>:jti (removes allowlisted jti → invalidates refresh)
  - auth:user:42:session:<sid> (removes index entry)
- Impact:
  - All devices’ refresh tokens fail on next use (since allowlisted jti keys are gone)
  - Access tokens expire soon (short TTL)

Why both keys are important

- auth:session:<sid>:jti: enforces single valid refresh per session and makes rotation device-scoped.
- auth:user:<userId>:session:<sid>: provides a fast, scalable way to find all sessionIds for a user (logout-all, list sessions, revoke one). Without this index you’d resort to slow key scans or extra metadata.

### Reuse policy options

- revoke_session: Only that device’s session is invalidated on reuse. Others remain signed in.
- revoke_all: All user sessions are invalidated on reuse (logout-all).
- lock_user: User account is temporarily locked on reuse; optionally revoke all sessions.
