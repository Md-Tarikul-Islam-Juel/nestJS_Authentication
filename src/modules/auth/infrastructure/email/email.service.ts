import {MailerService} from '@nestjs-modules/mailer';
import {Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {LoggerService} from '../../../../common/observability/logger.service';
import {AUTH_MESSAGES} from '../../../_shared/constants';
import {EmailServiceError} from '../../domain/errors/email-service-error.error';
import {EmailServicePort} from '../../domain/repositories/email.service.port';

/**
 * Email Service Implementation
 * Infrastructure adapter implementing EmailServicePort
 * Uses NestJS MailerService to send emails via SMTP
 */
@Injectable()
export class EmailServiceAdapter implements EmailServicePort {
  private readonly otpSenderMail: string;

  constructor(
    private config: ConfigService,
    private mailerService: MailerService,
    private logger: LoggerService
  ) {
    this.otpSenderMail = this.config.get<string>('authConfig.email.email');
  }

  async sendOtpEmail(email: string, otp: string, expireTime: number): Promise<void> {
    try {
      const mailOptions = {
        to: email,
        from: this.otpSenderMail,
        subject: AUTH_MESSAGES.EMAIL_SUBJECT,
        text: `Your OTP code is: ${otp}. It is valid for ${expireTime} minutes.`
      };

      // Add timeout for email sending (10 seconds)
      await Promise.race([
        this.mailerService.sendMail(mailOptions),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Email service timeout')), 10000))
      ]);

      this.logger.info({message: `OTP email sent successfully to ${email}`});
    } catch (error) {
      this.logger.error({
        message: AUTH_MESSAGES.FAILED_TO_SEND_OTP_EMAIL,
        details: {email, error: error instanceof Error ? error.message : String(error)}
      });
      throw new EmailServiceError(AUTH_MESSAGES.FAILED_TO_SEND_OTP_EMAIL);
    }
  }
}
