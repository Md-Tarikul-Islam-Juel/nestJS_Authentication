import {Inject, Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {PlatformJwtService, TokenConfig} from '../../../../platform/jwt/jwt.service';
import {AUTH_MESSAGES} from '../../../_shared/constants';
import {CommonAuthService} from '../../domain/services/common-auth.service';
import {OtpDomainService} from '../../domain/services/otp-domain.service';
import {LastActivityTrackService} from '../../infrastructure/services/last-activity-track.service';
import {OtpService} from '../../infrastructure/services/otp.service';
import {UserService} from '../../infrastructure/services/user.service';
import {VerifyOtpCommand} from '../commands/verify-otp.command';
import {UNIT_OF_WORK_PORT} from '../di-tokens';
import {Tokens} from '../dto/auth-base.dto';
import {SigninSuccessResponseDto} from '../dto/auth-response.dto';
import {UnitOfWorkPort} from '../uow/uow.port';

@Injectable()
export class VerifyOtpHandler {
  private readonly tokenConfig: TokenConfig;

  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UserService,
    private readonly otpService: OtpService,
    private readonly jwtService: PlatformJwtService,
    private readonly commonAuthService: CommonAuthService,
    private readonly lastActivityService: LastActivityTrackService,
    private readonly otpDomainService: OtpDomainService,
    @Inject(UNIT_OF_WORK_PORT)
    private readonly uow: UnitOfWorkPort
  ) {
    this.tokenConfig = {
      useJwe: this.configService.get<boolean>('authConfig.token.useJwe'),
      jweAccessTokenSecretKey: this.configService.get<string>('authConfig.token.jweAccessTokenSecretKey'),
      jwtAccessTokenSecretKey: this.configService.get<string>('authConfig.token.jwtAccessTokenSecretKey'),
      jweJwtAccessTokenExpireTime: this.configService.get<string>('authConfig.token.jweJwtAccessTokenExpireTime'),
      jweRefreshTokenSecretKey: this.configService.get<string>('authConfig.token.jweRefreshTokenSecretKey'),
      jwtRefreshTokenSecretKey: this.configService.get<string>('authConfig.token.jwtRefreshTokenSecretKey'),
      jweJwtRefreshTokenExpireTime: this.configService.get<string>('authConfig.token.jweJwtRefreshTokenExpireTime')
    };
  }

  async execute(command: VerifyOtpCommand): Promise<SigninSuccessResponseDto> {
    const existingUser = await this.userService.findUserByEmail(command.email);

    await this.verifyUserAndOtp(existingUser, command.otp);

    await this.uow.withTransaction(async tx => {
      await tx.user.update({
        where: {email: command.email},
        data: {verified: true}
      });
    });

    await this.otpService.deleteOtp(command.email);

    // Generate and update logoutPin for token validation
    const newLogoutPin = this.otpDomainService.generateOtp(6);
    await this.userService.updateLogoutPin(existingUser.id, newLogoutPin);

    // Update the user object with new logoutPin for token generation
    (existingUser as any).logoutPin = newLogoutPin;

    const sanitizedUserDataForToken = this.commonAuthService.removeSensitiveData(existingUser, [
      'password',
      'mfaEnabled',
      'failedOtpAttempts',
      'accountLockedUntil'
    ]);
    const sanitizedUserDataForResponse = this.commonAuthService.removeSensitiveData(existingUser, [
      'password',
      'verified',
      'isForgetPassword',
      'mfaEnabled',
      'failedOtpAttempts',
      'accountLockedUntil',
      'logoutPin',
      'authorizerId',
      'loginSource',
      'lastActivityAt'
    ]);

    await this.lastActivityService.updateLastActivityInDB(existingUser.id);

    const token: Tokens = await this.jwtService.generateTokens(sanitizedUserDataForToken, this.tokenConfig);
    return this.buildSigninResponse(sanitizedUserDataForResponse as any, token, AUTH_MESSAGES.OTP_AUTHORIZED);
  }

  private async verifyUserAndOtp(user: any, otp: string): Promise<void> {
    await this.otpService.verifyOtp(user.email, otp);
  }

  private buildSigninResponse(userData: any, tokens: Tokens, message: string): SigninSuccessResponseDto {
    return {
      success: true,
      message,
      tokens,
      data: {
        user: userData
      }
    };
  }
}
