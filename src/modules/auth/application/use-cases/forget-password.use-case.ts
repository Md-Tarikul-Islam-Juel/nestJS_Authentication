import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AUTH_MESSAGES } from '../../../_shared/constants';
import { EmailServiceError } from '../../domain/errors/email-service-error.error';
import { UserNotFoundError } from '../../domain/errors/user-not-found.error';
import type { EmailServicePort } from '../../domain/repositories/email.service.port';
import type { ForgetPasswordSuccessResponseDto } from '../../interface/dto/auth-response.dto';
import { ForgetPasswordCommand } from '../commands/forget-password.command';
import { EMAIL_SERVICE_PORT } from '../di-tokens';
import { OtpDomainService } from '../services/otp-domain.service';
import { OtpService } from '../services/otp.service';
import { UserService } from '../services/user.service';

@Injectable()
export class ForgetPasswordUseCase {
  private readonly otpExpireTime: number;

  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UserService,
    private readonly otpService: OtpService,
    @Inject(EMAIL_SERVICE_PORT)
    private readonly emailService: EmailServicePort,
    private readonly otpDomainService: OtpDomainService
  ) {
    this.otpExpireTime = this.configService.get<number>('authConfig.otp.otpExpireTime') ?? 5;
  }

  async execute(command: ForgetPasswordCommand): Promise<ForgetPasswordSuccessResponseDto> {
    const existingUser = await this.userService.findUserByEmail(command.email);

    if (!existingUser) {
      throw new UserNotFoundError(command.email);
    }

    try {
      const updatedData = await this.userService.updateForgotPasswordStatus(existingUser.email, true);
      if (updatedData.isForgetPassword === false) {
        throw new EmailServiceError(AUTH_MESSAGES.FAILED_TO_SEND_OTP_EMAIL);
      }

      const otp = this.otpDomainService.generateOtp(6);
      await this.otpService.storeOtp(existingUser.email, otp, this.otpExpireTime);
      await this.emailService.sendOtpEmail(existingUser.email, otp, this.otpExpireTime);

      return {
        success: true,
        message: AUTH_MESSAGES.OTP_EMAIL_SENT,
        data: {
          otp: {
            timeout: this.otpExpireTime,
            unit: 'mins'
          }
        }
      };
    } catch (error) {
      if (error instanceof EmailServiceError) {
        throw error;
      }
      throw new EmailServiceError(AUTH_MESSAGES.FAILED_TO_SEND_OTP_EMAIL);
    }
  }
}
