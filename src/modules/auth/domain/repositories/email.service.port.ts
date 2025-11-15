/**
 * Email Service Port
 * Domain layer abstraction for email operations
 * Following Clean Architecture: application depends on this abstraction, not concrete implementation
 */
export interface EmailServicePort {
  /**
   * Send OTP email to user
   * @param email - Recipient email address
   * @param otp - One-time password code
   * @param expireTime - OTP expiration time in minutes
   */
  sendOtpEmail(email: string, otp: string, expireTime: number): Promise<void>;
}
