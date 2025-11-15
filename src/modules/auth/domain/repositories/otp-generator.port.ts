/**
 * OTP Generator Port
 * Domain layer abstraction for OTP generation operations
 * Following Clean Architecture: application depends on this abstraction, not concrete implementation
 */
export interface OtpGeneratorPort {
  /**
   * Generate a numeric OTP of specified length
   * @param length - Length of the OTP (typically 6)
   * @returns Numeric OTP string
   */
  generate(length: number): string;

  /**
   * Validate OTP format (numeric and correct length)
   * @param otp - OTP string to validate
   * @param expectedLength - Expected length of the OTP
   * @returns True if OTP is valid format, false otherwise
   */
  validateLength(otp: string, expectedLength: number): boolean;
}
