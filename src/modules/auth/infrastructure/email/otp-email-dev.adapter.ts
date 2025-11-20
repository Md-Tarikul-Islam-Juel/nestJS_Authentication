import { Injectable } from '@nestjs/common';
import { LoggerService } from '../../../../common/observability/logger.service';
import { AUTH_MESSAGES } from '../../../_shared/constants';
import { EmailServiceError } from '../../domain/errors/email-service-error.error';
import { EmailServicePort } from '../../domain/repositories/email.service.port';
import { DevOtpStorageService } from '../cache/dev-otp-storage.service';

/**
 * Mock Email Service Adapter
 * Stores OTPs in dev viewer instead of sending emails
 * Used in development environment for testing
 */
@Injectable()
export class EmailServiceMockAdapter implements EmailServicePort {
  constructor(
    private devOtpStorage: DevOtpStorageService,
    private logger: LoggerService
  ) {}

  async sendOtpEmail(email: string, otp: string, expireTime: number): Promise<void> {
    try {
      // Store OTP in dev viewer instead of sending email
      await this.devOtpStorage.storeOtp(email, otp, expireTime);
      this.logger.info({message: `OTP stored in dev viewer for ${email}: ${otp}`});
    } catch (error) {
      this.logger.error({
        message: AUTH_MESSAGES.FAILED_TO_SEND_OTP_EMAIL,
        details: {email, error: error instanceof Error ? error.message : String(error)}
      });
      throw new EmailServiceError(AUTH_MESSAGES.FAILED_TO_SEND_OTP_EMAIL);
    }
  }
}
