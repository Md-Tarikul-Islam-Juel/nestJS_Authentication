import { Injectable, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { LoggerService } from '../../../../common/observability/logger.service';
import { EmailQueueService } from '../../../../platform/queue/services/email-queue.service';
import { AUTH_MESSAGES } from '../../../_shared/constants';
import { EmailServiceError } from '../../domain/errors/email-service-error.error';
import { EmailServicePort } from '../../domain/repositories/email.service.port';
import { DevOtpStorageService } from '../cache/dev-otp-storage.service';

/**
 * Email Service Implementation
 * Infrastructure adapter implementing EmailServicePort
 * Uses EmailQueueService to queue emails for async processing in production
 * Stores OTPs in dev storage for viewing in development mode
 */
@Injectable()
export class EmailServiceAdapter implements EmailServicePort {
  private readonly isDevelopment: boolean;

  constructor(
    private emailQueueService: EmailQueueService,
    private logger: LoggerService,
    private configService: ConfigService,
    @Optional() private devOtpStorage?: DevOtpStorageService
  ) {
    const nodeEnv = this.configService.get<string>('NODE_ENV', 'development');
    this.isDevelopment = nodeEnv === 'development';
  }

  async sendOtpEmail(email: string, otp: string, expireTime: number): Promise<void> {
    try {
      if (this.isDevelopment && this.devOtpStorage) {
        // Development mode: Store OTP for viewing, skip email queue
        await this.devOtpStorage.storeOtp(email, otp, expireTime);
        this.logger.info({message: `OTP stored in dev viewer for ${email}: ${otp}`});
      } else {
        // Production mode: Queue email for async sending
        await this.emailQueueService.addOtpEmailJob(email, otp, expireTime);
        this.logger.info({message: `OTP email queued successfully for ${email}`});
      }
    } catch (error) {
      this.logger.error({
        message: AUTH_MESSAGES.FAILED_TO_SEND_OTP_EMAIL,
        details: {email, error: error instanceof Error ? error.message : String(error)}
      });
      throw new EmailServiceError(AUTH_MESSAGES.FAILED_TO_SEND_OTP_EMAIL);
    }
  }
}
