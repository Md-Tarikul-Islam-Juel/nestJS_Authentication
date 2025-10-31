import {Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {AUTH_MESSAGES} from '../../../_shared/constants';
import {EmailServiceError} from '../../domain/errors/email-service-error.error';
import {UserNotFoundError} from '../../domain/errors/user-not-found.error';
import {OtpDomainService} from '../../domain/services/otp-domain.service';
import {EmailService} from '../../infrastructure/email/email.service';
import {OtpService} from '../../infrastructure/services/otp.service';
import {UserService} from '../../infrastructure/services/user.service';
import {ForgetPasswordCommand} from '../commands/forget-password.command';
import {ForgetPasswordSuccessResponseDto} from '../dto/auth-response.dto';

@Injectable()
export class ForgetPasswordHandler {
  private readonly otpExpireTime: number;

  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UserService,
    private readonly otpService: OtpService,
    private readonly emailService: EmailService,
    private readonly otpDomainService: OtpDomainService
  ) {
    this.otpExpireTime = this.configService.get<number>('authConfig.otp.otpExpireTime');
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
