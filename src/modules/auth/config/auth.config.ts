import {registerAs} from '@nestjs/config';

export default registerAs('authConfig', () => ({
  bcryptSaltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) ?? 14, // default to 14 rounds

  token: {
    jweAccessTokenSecretKey: process.env.JWE_ACCESS_TOKEN_SECRET ?? '1234567890abcdef1234567890abcdef',
    jwtAccessTokenSecretKey: process.env.JWT_ACCESS_TOKEN_SECRET ?? 'abcdefghijklmnopqrstuvwxyza123456',
    jweJwtAccessTokenExpireTime: process.env.JWE_JWT_ACCESS_TOKEN_EXPIRATION ?? '86400s', // default to 1 day
    jweRefreshTokenSecretKey: process.env.JWE_REFRESH_TOKEN_SECRET ?? 'abcdef1234567890abcdef1234567890',
    jwtRefreshTokenSecretKey: process.env.JWT_REFRESH_TOKEN_SECRET ?? 'abcdefghijklmnopqrstuvwxz1234567',
    jweJwtRefreshTokenExpireTime: process.env.JWE_JWT_REFRESH_TOKEN_EXPIRATION ?? '30d' // default to 30 days
  },

  otp: {
    otpExpireTime: parseInt(process.env.OTP_EXPIRE_TIME, 10) ?? 5, // default to 5 min
    otpMaxFailedAttempts: parseInt(process.env.OTP_MAX_FAILED_ATTEMPTS, 10) ?? 5, // default to 5 attempts
    otpLockoutTime: parseInt(process.env.OTP_LOCKOUT_TIME, 10) ?? 5 // default to 5 min lockout time
  },

  password: {
    minLength: parseInt(process.env.PASSWORD_MIN_LENGTH, 10) ?? 8, // default to 8 characters
    maxLength: parseInt(process.env.PASSWORD_MAX_LENGTH, 10) ?? 32, // default to 32 characters
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
    port: parseInt(process.env.OTP_SENDER_MAIL_PORT, 10), // default to 587 for non-secure SMTP
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
    port: parseInt(process.env.REDIS_PORT, 10),
    cacheExpiration: parseInt(process.env.REDIS_CACHE_EXPIRATION, 10)
  },

  database: {
    host: process.env.DATABASE_HOST,
    port: parseInt(process.env.DATABASE_PORT, 10),
    user: process.env.DATABASE_USER,
    password: process.env.DATABASE_PASSWORD,
    name: process.env.DATABASE_NAME,
    url: process.env.DATABASE_URL
  }
}));
