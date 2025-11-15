import {Inject, Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import type {TokenConfig} from '../../domain/repositories/jwt-service.port';
import {JWT_SERVICE_PORT} from '../di-tokens';
import {AUTH_MESSAGES} from '../../../_shared/constants';
import {LoginSource} from '../../domain/enums/login-source.enum';
import type {JwtServicePort} from '../../domain/repositories/jwt-service.port';
import type {ExistingUserInterface} from '../types/auth.types';
import {CommonAuthService} from '../services/common-auth.service';
import {OtpDomainService} from '../services/otp-domain.service';
import {PasswordPolicyService} from '../services/password-policy.service';
import {LastActivityTrackService} from '../services/last-activity-track.service';
import {UserService} from '../services/user.service';
import {createTokenConfig} from './token-config.factory';
import {OAuthSignInCommand} from '../commands/oauth-sign-in.command';
import type {Tokens} from '../../interface/dto/auth-base.dto';
import type {SigninSuccessResponseDto} from '../../interface/dto/auth-response.dto';
import {UserMapper, UserMapperInput} from '../mappers/user.mapper';

@Injectable()
export class OAuthSignInUseCase {
  private readonly saltRounds: number;
  private readonly tokenConfig: TokenConfig;

  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UserService,
    @Inject(JWT_SERVICE_PORT)
    private readonly jwtService: JwtServicePort,
    private readonly passwordService: PasswordPolicyService,
    private readonly commonAuthService: CommonAuthService,
    private readonly otpDomainService: OtpDomainService,
    private readonly lastActivityService: LastActivityTrackService
  ) {
    this.saltRounds = this.configService.get<number>('authConfig.bcryptSaltRounds');
    this.tokenConfig = createTokenConfig(this.configService);
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
    const userWithLogoutPin: ExistingUserInterface & {logoutPin: string} = {...existingUser, logoutPin: newLogoutPin};

    const sanitizedUserDataForToken = this.commonAuthService.sanitizeForToken(userWithLogoutPin, ['password']);
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

    return this.buildSigninResponse(
      sanitizeForMapper(sanitizedUserDataForResponse),
      tokens,
      AUTH_MESSAGES.SIGNIN_SUCCESSFUL
    );
  }

  private buildSigninResponse(userData: UserMapperInput, tokens: Tokens, message: string): SigninSuccessResponseDto {
    return {
      success: true,
      message,
      tokens,
      data: {
        user: UserMapper.toSignInResponse(userData)
      }
    };
  }
}

function sanitizeForMapper(user: Record<string, any>): UserMapperInput {
  return {
    id: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName
  };
}
