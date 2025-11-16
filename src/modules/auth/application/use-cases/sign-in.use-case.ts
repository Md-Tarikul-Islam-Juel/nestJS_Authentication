import {Inject, Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {JtiProvider} from '../../../../platform/jwt/jti.provider';
import {JtiAllowlistService} from '../../../../platform/redis/jti-allowlist.service';
import {UserSessionIndexService} from '../../../../platform/redis/user-session-index.service';
import {AUTH_MESSAGES} from '../../../_shared/constants';
import {InvalidCredentialsError} from '../../domain/errors/invalid-credentials.error';
import {UserNotFoundError} from '../../domain/errors/user-not-found.error';
import {UserNotVerifiedError} from '../../domain/errors/user-not-verified.error';
import type {EmailServicePort} from '../../domain/repositories/email.service.port';
import type {JwtServicePort, TokenConfig} from '../../domain/repositories/jwt-service.port';
import type {LoggerPort} from '../../domain/repositories/logger.port';
import type {Tokens} from '../../interface/dto/auth-base.dto';
import type {SigninSuccessResponseDto} from '../../interface/dto/auth-response.dto';
import {SignInCommand} from '../commands/sign-in.command';
import {EMAIL_SERVICE_PORT, JWT_SERVICE_PORT, LOGGER_PORT} from '../di-tokens';
import {UserMapper, UserMapperInput} from '../mappers/user.mapper';
import {CommonAuthService} from '../services/common-auth.service';
import {LastActivityTrackService} from '../services/last-activity-track.service';
import {OtpDomainService} from '../services/otp-domain.service';
import {OtpService} from '../services/otp.service';
import {UserService} from '../services/user.service';
import {createTokenConfig} from './token-config.factory';

@Injectable()
export class SignInUseCase {
  private readonly otpExpireTime: number;
  private readonly tokenConfig: TokenConfig;

  constructor(
    private readonly configService: ConfigService,
    @Inject(LOGGER_PORT)
    private readonly logger: LoggerPort,
    private readonly userService: UserService,
    private readonly otpService: OtpService,
    @Inject(JWT_SERVICE_PORT)
    private readonly jwtService: JwtServicePort,
    @Inject(EMAIL_SERVICE_PORT)
    private readonly emailService: EmailServicePort,
    private readonly commonAuthService: CommonAuthService,
    private readonly otpDomainService: OtpDomainService,
    private readonly lastActivityService: LastActivityTrackService,
    private readonly jtiProvider: JtiProvider,
    private readonly jtiAllowlist: JtiAllowlistService,
    private readonly userSessionIndex: UserSessionIndexService
  ) {
    this.otpExpireTime = this.configService.get<number>('authConfig.otp.otpExpireTime');
    this.tokenConfig = createTokenConfig(this.configService);
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

      // Log unexpected errors for debugging (PII automatically masked)
      this.logger.error('Unexpected error during user authentication', 'SignInUseCase', error instanceof Error ? error.stack : undefined, {
        email: command.email,
        error: error instanceof Error ? error.message : String(error),
        errorType: error?.constructor?.name || 'Unknown'
      });

      throw new InvalidCredentialsError();
    }

    await this.userService.updateForgotPasswordStatus(existingUser.email, false);

    if (existingUser.mfaEnabled) {
      const otp = this.otpDomainService.generateOtp(6);
      const otpExpireTime = this.otpExpireTime || 5;
      await this.otpService.storeOtp(existingUser.email, otp, otpExpireTime);
      await this.emailService.sendOtpEmail(existingUser.email, otp, otpExpireTime);

      this.logger.info({message: `MFA enabled for user ${existingUser.email}, OTP sent.`});

      return {
        success: true,
        message: 'Please check your email for a verification code to complete sign-in.',
        mfa: {
          enabled: true,
          type: 'email'
        }
      };
    }

    const sanitizedUserDataForToken = this.commonAuthService.sanitizeForToken(existingUser, ['password']);
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

    // Generate session and jti, allowlist in Redis for rotation checks
    const sessionId = this.jtiProvider.generateSessionId();
    const jti = this.jtiProvider.generateJti();

    const refreshTtlSeconds = toSeconds(this.tokenConfig.jweJwtRefreshTokenExpireTime);
    await this.jtiAllowlist.setCurrentJtiForSession(sessionId, jti, refreshTtlSeconds);
    // Track session for user (for logout-all)
    await this.userSessionIndex.addSession(existingUser.id, sessionId, refreshTtlSeconds);

    const tokens: Tokens = await this.jwtService.generateTokens({...sanitizedUserDataForToken, sid: sessionId, jti}, this.tokenConfig);

    return this.buildSigninResponse(sanitizeForMapper(sanitizedUserDataForResponse), tokens, AUTH_MESSAGES.SIGNIN_SUCCESSFUL);
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

function toSeconds(duration: string): number {
  const trimmed = String(duration).trim();
  const match = /^(\d+)\s*([smhd])?$/i.exec(trimmed);
  if (!match) {
    const n = parseInt(trimmed, 10);
    return Number.isFinite(n) ? n : 0;
  }
  const value = parseInt(match[1], 10);
  const unit = (match[2] || 's').toLowerCase();
  switch (unit) {
    case 's':
      return value;
    case 'm':
      return value * 60;
    case 'h':
      return value * 3600;
    case 'd':
      return value * 86400;
    default:
      return value;
  }
}
