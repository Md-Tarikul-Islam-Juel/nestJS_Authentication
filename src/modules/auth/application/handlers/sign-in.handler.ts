import {Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {LoggerService} from '../../../../common/observability/logger.service';
import {PlatformJwtService, TokenConfig} from '../../../../platform/jwt/jwt.service';
import {AUTH_MESSAGES} from '../../../_shared/constants';
import {InvalidCredentialsError} from '../../domain/errors/invalid-credentials.error';
import {UserNotFoundError} from '../../domain/errors/user-not-found.error';
import {UserNotVerifiedError} from '../../domain/errors/user-not-verified.error';
import {CommonAuthService} from '../../domain/services/common-auth.service';
import {OtpDomainService} from '../../domain/services/otp-domain.service';
import {EmailService} from '../../infrastructure/email/email.service';
import {LastActivityTrackService} from '../../infrastructure/services/last-activity-track.service';
import {OtpService} from '../../infrastructure/services/otp.service';
import {UserService} from '../../infrastructure/services/user.service';
import {SignInCommand} from '../commands/sign-in.command';
import {Tokens} from '../dto/auth-base.dto';
import {SigninSuccessResponseDto} from '../dto/auth-response.dto';

@Injectable()
export class SignInHandler {
  private readonly otpExpireTime: number;
  private readonly tokenConfig: TokenConfig;

  constructor(
    private readonly configService: ConfigService,
    private readonly logger: LoggerService,
    private readonly userService: UserService,
    private readonly otpService: OtpService,
    private readonly jwtService: PlatformJwtService,
    private readonly emailService: EmailService,
    private readonly commonAuthService: CommonAuthService,
    private readonly otpDomainService: OtpDomainService,
    private readonly lastActivityService: LastActivityTrackService
  ) {
    this.otpExpireTime = this.configService.get<number>('authConfig.otp.otpExpireTime');
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

  async execute(command: SignInCommand): Promise<SigninSuccessResponseDto> {
    const existingUser = await this.userService.findUserByEmail(command.email);

    if (!existingUser) {
      throw new UserNotFoundError(command.email);
    }

    await this.lastActivityService.updateLastActivityInDB(existingUser.id);

    try {
      this.userService.authenticateUser(existingUser, command.password);
    } catch (error) {
      if (error instanceof InvalidCredentialsError || error instanceof UserNotVerifiedError) {
        throw error;
      }
      throw new InvalidCredentialsError();
    }

    await this.userService.updateForgotPasswordStatus(existingUser.email, false);

    // Generate and update logoutPin for token validation
    const newLogoutPin = this.otpDomainService.generateOtp(6);
    await this.userService.updateLogoutPin(existingUser.id, newLogoutPin);

    // Update the user object with new logoutPin for token generation
    (existingUser as any).logoutPin = newLogoutPin;

    if (existingUser.mfaEnabled) {
      const otp = this.otpDomainService.generateOtp(6);
      const otpExpireTime = this.otpExpireTime || 5;
      await this.otpService.storeOtp(existingUser.email, otp, otpExpireTime);
      await this.emailService.sendOtpEmail(existingUser.email, otp, otpExpireTime);

      this.logger.info(`MFA enabled for user ${existingUser.email}, OTP sent.`, 'SignInHandler.execute()');

      return {
        success: true,
        message: 'Please check your email for a verification code to complete sign-in.',
        mfa: {
          enabled: true,
          type: 'email'
        }
      };
    }

    const sanitizedUserDataForToken = this.commonAuthService.removeSensitiveData(existingUser, ['password']);
    const sanitizedUserDataForResponse = this.commonAuthService.removeSensitiveData(existingUser, [
      'password',
      'verified',
      'isForgetPassword',
      'logoutPin',
      'authorizerId',
      'loginSource',
      'lastActivityAt',
      'accountLockedUntil',
      'mfaEnabled',
      'failedOtpAttempts',
      'updatedAt'
    ]);

    const tokens: Tokens = await this.jwtService.generateTokens(sanitizedUserDataForToken, this.tokenConfig);

    return this.buildSigninResponse(sanitizedUserDataForResponse as any, tokens, AUTH_MESSAGES.SIGNIN_SUCCESSFUL);
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
