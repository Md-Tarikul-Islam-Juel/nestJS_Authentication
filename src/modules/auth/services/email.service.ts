import { Injectable, InternalServerErrorException } from '@nestjs/common';
import { MailerService } from '@nestjs-modules/mailer';
import { LoggerService } from '../../logger/logger.service';
import { emailSubject, failedToSendOTPEmail } from '../utils/string';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class EmailService {
  private readonly otpSenderMail: string;

  constructor(
    private config: ConfigService,
    private mailerService: MailerService,
    private logger: LoggerService) {
    this.otpSenderMail = this.config.get<string>('authConfig.email.email');
  }

  async sendOtpEmail(email: string, otp: string, expireTime: number): Promise<void> {
    try {
      const mailOptions = {
        to: email,
        from: this.otpSenderMail,
        subject: emailSubject,
        text: `Your OTP code is: ${otp}. It is valid for ${expireTime} minutes.`,
      };

      await this.mailerService.sendMail(mailOptions);
    } catch (error) {
      this.logger.error({
        message: `${failedToSendOTPEmail}`,
        details: email,
      });
      console.error(failedToSendOTPEmail, error);
      throw new InternalServerErrorException(failedToSendOTPEmail);
    }
  }
}
