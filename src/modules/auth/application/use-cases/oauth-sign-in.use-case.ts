import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AUTH_MESSAGES } from '../../../_shared/constants';
import { LoginSource } from '../../domain/enums/login-source.enum';
import type { JwtServicePort, TokenConfig } from '../../domain/repositories/jwt-service.port';
import type { Tokens } from '../../interface/dto/auth-base.dto';
import type { SigninSuccessResponseDto } from '../../interface/dto/auth-response.dto';
import { OAuthSignInCommand } from '../commands/oauth-sign-in.command';
import { JWT_SERVICE_PORT } from '../di-tokens';
import { UserMapper, UserMapperInput } from '../mappers/user.mapper';
import { CommonAuthService } from '../services/common-auth.service';
import { LastActivityTrackService } from '../services/last-activity-track.service';
import { OtpDomainService } from '../services/otp-domain.service';
import { PasswordPolicyService } from '../services/password-policy.service';
import { UserService } from '../services/user.service';
import type { ExistingUserInterface } from '../types/auth.types';
import { createTokenConfig } from './token-config.factory';

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
    this.saltRounds = this.configService.get<number>('authConfig.bcryptSaltRounds') ?? 10;
    this.tokenConfig = createTokenConfig(this.configService);
  }

  async execute(command: OAuthSignInCommand): Promise<SigninSuccessResponseDto> {
    const {email, loginSource, authorizerId} = command;

    let existingUser = await this.userService.findUserByEmail(email);

    if (!existingUser) {
      // Register new user via OAuth
      const randomPassword = this.otpDomainService.generateOtp(10);
      const hashedPassword = await this.passwordService.hashPassword(randomPassword, this.saltRounds);
      
      // Create user payload
      const newUserPayload = {
        email: command.email,
        firstName: command.firstName ?? '',
        lastName: command.lastName ?? '',
        loginSource: command.loginSource,
        mfaEnabled: command.mfaEnabled
      };

      existingUser = await this.userService.createUser(
        newUserPayload as any, // Casting to any to avoid DTO strict issues for now, or we should import SignupDto
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
