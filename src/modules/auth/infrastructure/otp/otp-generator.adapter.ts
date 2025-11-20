import { Injectable } from '@nestjs/common';
import * as otpGenerator from 'otp-generator';
import type { OtpGeneratorPort } from '../../domain/repositories/otp-generator.port';

/**
 * OTP Generator Adapter
 * Infrastructure layer implementation of OtpGeneratorPort using otp-generator library
 * Following Clean Architecture: implements domain port using infrastructure technology
 */
@Injectable()
export class OtpGeneratorAdapter implements OtpGeneratorPort {
  /**
   * Generate a numeric OTP of specified length using otp-generator library
   * @param length - Length of the OTP (typically 6)
   * @returns Numeric OTP string
   */
  generate(length: number): string {
    return otpGenerator.generate(length, {
      digits: true,

      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false
    });
  }

  /**
   * Validate OTP format (numeric and correct length)
   * @param otp - OTP string to validate
   * @param expectedLength - Expected length of the OTP
   * @returns True if OTP is valid format, false otherwise
   */
  validateLength(otp: string, expectedLength: number): boolean {
    return otp.length === expectedLength && /^\d+$/.test(otp);
  }
}
