// Dependency Injection Tokens for Auth Module
// Note: UNIT_OF_WORK_PORT is now in src/common/persistence/uow/di-tokens.ts (shared across modules)
export const USER_REPOSITORY_PORT = Symbol('UserRepositoryPort');
export const EMAIL_SERVICE_PORT = Symbol('EmailServicePort');
export const OTP_CACHE_PORT = Symbol('OtpCachePort');
export const ACTIVITY_CACHE_PORT = Symbol('ActivityCachePort');
export const JWT_SERVICE_PORT = Symbol('JwtServicePort');
export const LOGGER_PORT = Symbol('LoggerPort');
export const PASSWORD_HASHER_PORT = Symbol('PasswordHasherPort');
export const OTP_GENERATOR_PORT = Symbol('OtpGeneratorPort');
