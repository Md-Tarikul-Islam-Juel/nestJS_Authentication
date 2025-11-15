import {Inject, Injectable} from '@nestjs/common';
import type {OtpGeneratorPort} from '../../domain/repositories/otp-generator.port';
import {OTP_GENERATOR_PORT} from '../di-tokens';

/**
 * OTP Domain Service
 * Application layer service for OTP generation and validation
 * Following Clean Architecture: uses domain port, not infrastructure directly
 */
@Injectable()
export class OtpDomainService {
  constructor(
    @Inject(OTP_GENERATOR_PORT)
    private readonly otpGenerator: OtpGeneratorPort
  ) {}

  generateOtp(length: number): string {
    return this.otpGenerator.generate(length);
  }

  validateOtpLength(otp: string, expectedLength: number): boolean {
    return this.otpGenerator.validateLength(otp, expectedLength);
  }
}
