import { Injectable } from '@nestjs/common';
import { LoggerService } from '../../../../common/observability/logger.service';
import { EmailQueueService } from '../../../../platform/queue/services/email-queue.service';
import { AUTH_MESSAGES } from '../../../_shared/constants';
import { EmailServiceError } from '../../domain/errors/email-service-error.error';
import { EmailServicePort } from '../../domain/repositories/email.service.port';

/**
 * Production Email Service Adapter
 * Sends emails via BullMQ queue for async processing
 * Used in production environment
 */
@Injectable()
export class EmailServiceProductionAdapter implements EmailServicePort {
  constructor(
    private emailQueueService: EmailQueueService,
    private logger: LoggerService
  ) {}

  async sendOtpEmail(email: string, otp: string, expireTime: number): Promise<void> {
    try {
      // Queue email for async sending
      await this.emailQueueService.addOtpEmailJob(email, otp, expireTime);
      this.logger.info({message: `OTP email queued successfully for ${email}`});
    } catch (error) {
      this.logger.error({
        message: AUTH_MESSAGES.FAILED_TO_SEND_OTP_EMAIL,
        details: {email, error: error instanceof Error ? error.message : String(error)}
      });
      throw new EmailServiceError(AUTH_MESSAGES.FAILED_TO_SEND_OTP_EMAIL);
    }
  }
}
