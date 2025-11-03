import {Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {PlatformJwtService, TokenConfig} from '../../../../platform/jwt/jwt.service';
import {AUTH_MESSAGES} from '../../../_shared/constants';
import {LoginSource} from '../../domain/enums/login-source.enum';
import {CommonAuthService} from '../../domain/services/common-auth.service';
import {OtpDomainService} from '../../domain/services/otp-domain.service';
import {PasswordPolicyService} from '../../domain/services/password-policy.service';
import {LastActivityTrackService} from '../../infrastructure/services/last-activity-track.service';
import {UserService} from '../../infrastructure/services/user.service';
import {OAuthSignInCommand} from '../commands/oauth-sign-in.command';
import {Tokens} from '../dto/auth-base.dto';
import {SigninSuccessResponseDto} from '../dto/auth-response.dto';

@Injectable()
export class OAuthSignInHandler {
  private readonly saltRounds: number;
  private readonly tokenConfig: TokenConfig;

  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UserService,
    private readonly jwtService: PlatformJwtService,
    private readonly passwordService: PasswordPolicyService,
    private readonly commonAuthService: CommonAuthService,
    private readonly otpDomainService: OtpDomainService,
    private readonly lastActivityService: LastActivityTrackService
  ) {
    this.saltRounds = this.configService.get<number>('authConfig.bcryptSaltRounds');
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

  async execute(command: OAuthSignInCommand): Promise<SigninSuccessResponseDto> {
    let existingUser = await this.userService.findUserByEmail(command.email);

    if (!existingUser) {
      const randomPassword = this.otpDomainService.generateOtp(10);
      const hashedPassword = await this.passwordService.hashPassword(randomPassword, this.saltRounds);
      existingUser = await this.userService.createUser(
        {
          email: command.email,
          firstName: command.firstName,
          lastName: command.lastName,
          loginSource: command.loginSource,
          mfaEnabled: command.mfaEnabled
        },
        hashedPassword,
        command.loginSource as LoginSource,
        true
      );
    }

    // Generate and update logoutPin for token validation
    const newLogoutPin = this.otpDomainService.generateOtp(6);
    await this.userService.updateLogoutPin(existingUser.id, newLogoutPin);

    // Update the user object with new logoutPin for token generation
    (existingUser as any).logoutPin = newLogoutPin;

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

    await this.lastActivityService.updateLastActivityInDB(existingUser.id);

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
