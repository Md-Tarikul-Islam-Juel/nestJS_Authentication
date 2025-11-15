/**
 * OTP Cache Port
 * Domain layer abstraction for OTP caching operations
 * Following Clean Architecture: application depends on this abstraction, not concrete implementation
 */
export interface OtpCachePort {
  /**
   * Store OTP in cache
   * @param email - User email address (used as cache key)
   * @param otp - One-time password code to store
   * @param ttlSeconds - Time-to-live in seconds
   */
  store(email: string, otp: string, ttlSeconds: number): Promise<void>;

  /**
   * Retrieve OTP from cache
   * @param email - User email address (used as cache key)
   * @returns OTP string if found, null otherwise
   */
  get(email: string): Promise<string | null>;

  /**
   * Delete OTP from cache
   * @param email - User email address (used as cache key)
   */
  delete(email: string): Promise<void>;
}

