import {Inject, Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {EMAIL_SERVICE_PORT} from '../di-tokens';
import {AUTH_MESSAGES} from '../../../_shared/constants';
import {AccountLockedError} from '../../domain/errors/account-locked.error';
import type {EmailServicePort} from '../../domain/repositories/email.service.port';
import {OtpDomainService} from '../services/otp-domain.service';
import {OtpService} from '../services/otp.service';
import {UserService} from '../services/user.service';
import {ResendOtpCommand} from '../commands/resend-otp.command';
import type {ResendSuccessResponseDto} from '../../interface/dto/auth-response.dto';

@Injectable()
export class ResendOtpUseCase {
  private readonly otpExpireTime: number;

  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UserService,
    private readonly otpService: OtpService,
    @Inject(EMAIL_SERVICE_PORT)
    private readonly emailService: EmailServicePort,
    private readonly otpDomainService: OtpDomainService
  ) {
    this.otpExpireTime = this.configService.get<number>('authConfig.otp.otpExpireTime');
  }

  async execute(command: ResendOtpCommand): Promise<ResendSuccessResponseDto> {
    const existingUser = await this.userService.findUserByEmail(command.email);

    if (existingUser.accountLockedUntil && new Date() < existingUser.accountLockedUntil) {
      const remainingLockTime = Math.round((existingUser.accountLockedUntil.getTime() - Date.now()) / 60000);
      throw new AccountLockedError(remainingLockTime);
    }

    return this.sendOtp(command.email);
  }

  private async sendOtp(email: string): Promise<ResendSuccessResponseDto> {
    const otp = this.otpDomainService.generateOtp(6);
    await this.otpService.storeOtp(email, otp, this.otpExpireTime);
    await this.emailService.sendOtpEmail(email, otp, this.otpExpireTime);

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
  }
}
