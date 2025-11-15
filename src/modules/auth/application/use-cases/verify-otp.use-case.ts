import {Inject, Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {UNIT_OF_WORK_PORT} from '../../../../common/persistence/uow/di-tokens';
import {UnitOfWorkPort} from '../../../../common/persistence/uow/uow.port';
import {AUTH_MESSAGES} from '../../../_shared/constants';
import type {JwtServicePort, TokenConfig} from '../../domain/repositories/jwt-service.port';
import type {Tokens} from '../../interface/dto/auth-base.dto';
import type {SigninSuccessResponseDto} from '../../interface/dto/auth-response.dto';
import {VerifyOtpCommand} from '../commands/verify-otp.command';
import {JWT_SERVICE_PORT} from '../di-tokens';
import {UserMapper, UserMapperInput} from '../mappers/user.mapper';
import {CommonAuthService} from '../services/common-auth.service';
import {LastActivityTrackService} from '../services/last-activity-track.service';
import {OtpDomainService} from '../services/otp-domain.service';
import {OtpService} from '../services/otp.service';
import {UserService} from '../services/user.service';
import type {ExistingUserInterface} from '../types/auth.types';
import {createTokenConfig} from './token-config.factory';

@Injectable()
export class VerifyOtpUseCase {
  private readonly tokenConfig: TokenConfig;

  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UserService,
    private readonly otpService: OtpService,
    @Inject(JWT_SERVICE_PORT)
    private readonly jwtService: JwtServicePort,
    private readonly commonAuthService: CommonAuthService,
    private readonly lastActivityService: LastActivityTrackService,
    private readonly otpDomainService: OtpDomainService,
    @Inject(UNIT_OF_WORK_PORT)
    private readonly uow: UnitOfWorkPort
  ) {
    this.tokenConfig = createTokenConfig(this.configService);
  }

  async execute(command: VerifyOtpCommand): Promise<SigninSuccessResponseDto> {
    const existingUser = await this.userService.findUserByEmail(command.email);

    await this.verifyUserAndOtp(existingUser, command.otp);

    await this.uow.withTransaction(async tx => {
      await tx.user.update({
        where: {
          email: command.email,
          deletedAt: null // Soft delete: only update active users
        },
        data: {
          verified: true
        }
      });
    });

    await this.otpService.deleteOtp(command.email);

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
    return this.buildSigninResponse(sanitizeForMapper(sanitizedUserDataForResponse), token, AUTH_MESSAGES.OTP_AUTHORIZED);
  }

  private async verifyUserAndOtp(user: ExistingUserInterface, otp: string): Promise<void> {
    await this.otpService.verifyOtp(user.email, otp);
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
