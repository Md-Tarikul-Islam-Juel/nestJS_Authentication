import { registerAs } from '@nestjs/config';

export default registerAs('authConfig', () => ({
  bcryptSaltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS ?? '14', 10),

  token: {
    useJwe: process.env.USE_JWE?.toLowerCase() === 'true' || process.env.USE_JWE === undefined, // default to true
    jweAccessTokenSecretKey: process.env.JWE_ACCESS_TOKEN_SECRET ?? '1234567890abcdef1234567890abcdef',
    jwtAccessTokenSecretKey: process.env.JWT_ACCESS_TOKEN_SECRET ?? 'abcdefghijklmnopqrstuvwxyza123456',
    jweJwtAccessTokenExpireTime: process.env.JWE_JWT_ACCESS_TOKEN_EXPIRATION ?? '86400s', // default to 1 day
    jweRefreshTokenSecretKey: process.env.JWE_REFRESH_TOKEN_SECRET ?? 'abcdef1234567890abcdef1234567890',
    jwtRefreshTokenSecretKey: process.env.JWT_REFRESH_TOKEN_SECRET ?? 'abcdefghijklmnopqrstuvwxz1234567',
    jweJwtRefreshTokenExpireTime: process.env.JWE_JWT_REFRESH_TOKEN_EXPIRATION ?? '30d', // default to 30 days
    jti: {
      strategy: process.env.REFRESH_JTI_STRATEGY ?? 'uuid', // uuid | nanoid | random-bytes
      length: parseInt(process.env.REFRESH_JTI_LENGTH ?? '21', 10),
      prefix: process.env.REFRESH_JTI_PREFIX ?? ''
    },
    session: {
      prefix: process.env.SESSION_ID_PREFIX ?? 'sid_'
    },
    redis: {
      prefix: process.env.AUTH_REDIS_PREFIX ?? 'auth:'
    },
    reusePolicy: process.env.REFRESH_REUSE_POLICY ?? 'revoke_session', // revoke_session | revoke_all | lock_user
    enforceNoStore: (process.env.AUTH_NO_STORE ?? 'true').toLowerCase() === 'true'
  },

  otp: {
    otpExpireTime: parseInt(process.env.OTP_EXPIRE_TIME ?? '5', 10),
    otpMaxFailedAttempts: parseInt(process.env.OTP_MAX_FAILED_ATTEMPTS ?? '5', 10),
    otpLockoutTime: parseInt(process.env.OTP_LOCKOUT_TIME ?? '5', 10)
  },

  password: {
    minLength: parseInt(process.env.PASSWORD_MIN_LENGTH ?? '8', 10),
    maxLength: parseInt(process.env.PASSWORD_MAX_LENGTH ?? '32', 10),
    requireLowercase: process.env.PASSWORD_REQUIRE_LOWERCASE ?? true, // default to true
    requireUppercase: process.env.PASSWORD_REQUIRE_UPPERCASE ?? true, // default to true
    requireNumbers: process.env.PASSWORD_REQUIRE_NUMBERS ?? true, // default to true
    requireSpecialCharacters: process.env.PASSWORD_REQUIRE_SPECIAL_CHARACTERS ?? true, // default to true
    disallowRepeating: process.env.PASSWORD_DISALLOW_REPEATING ?? true, // default to true
    disallowSequential: process.env.PASSWORD_DISALLOW_SEQUENTIAL ?? true, // default to true
    blacklistCommon: process.env.PASSWORD_BLACKLIST_COMMON ?? true, // default to true
    excludeUsername: process.env.PASSWORD_EXCLUDE_USERNAME ?? true // default to true
  },

  email: {
    host: process.env.OTP_SENDER_MAIL_HOST,
    port: parseInt(process.env.OTP_SENDER_MAIL_PORT ?? '587', 10),
    email: process.env.OTP_SENDER_MAIL,
    pass: process.env.OTP_SENDER_MAIL_PASSWORD
  },

  oauth: {
    google: {
      clientId: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackUrl: process.env.GOOGLE_CALLBACK_URL
    },
    facebook: {
      clientId: process.env.FACEBOOK_CLIENT_ID,
      clientSecret: process.env.FACEBOOK_CLIENT_SECRET,
      callbackUrl: process.env.FACEBOOK_CALLBACK_URL
    }
  },

  redis: {
    host: process.env.REDIS_HOST,
    port: parseInt(process.env.REDIS_PORT ?? '6379', 10),
    cacheExpiration: parseInt(process.env.REDIS_CACHE_EXPIRATION ?? '3600', 10)
  },

  database: {
    host: process.env.DATABASE_HOST,
    port: parseInt(process.env.DATABASE_PORT ?? '5432', 10),
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    name: process.env.DATABASE_NAME,
    url: process.env.DATABASE_URL
  }
}));
