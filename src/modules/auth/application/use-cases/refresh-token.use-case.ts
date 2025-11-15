import {Inject, Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import type {TokenConfig} from '../../domain/repositories/jwt-service.port';
import {JWT_SERVICE_PORT} from '../di-tokens';
import {AUTH_MESSAGES} from '../../../_shared/constants';
import {UserNotFoundError} from '../../domain/errors/user-not-found.error';
import {UserNotVerifiedError} from '../../domain/errors/user-not-verified.error';
import type {JwtServicePort} from '../../domain/repositories/jwt-service.port';
import {CommonAuthService} from '../services/common-auth.service';
import {UserService} from '../services/user.service';
import {createTokenConfig} from './token-config.factory';
import {RefreshTokenCommand} from '../commands/refresh-token.command';
import type {Tokens} from '../../interface/dto/auth-base.dto';
import type {RefreshTokenSuccessResponseDto} from '../../interface/dto/auth-response.dto';

@Injectable()
export class RefreshTokenUseCase {
  private readonly tokenConfig: TokenConfig;

  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UserService,
    @Inject(JWT_SERVICE_PORT)
    private readonly jwtService: JwtServicePort,
    private readonly commonAuthService: CommonAuthService
  ) {
    this.tokenConfig = createTokenConfig(this.configService);
  }

  async execute(command: RefreshTokenCommand): Promise<RefreshTokenSuccessResponseDto> {
    const existingUser = await this.userService.findUserByEmail(command.email);

    if (!existingUser) {
      throw new UserNotFoundError(command.email);
    }

    // Verify user is verified before generating new tokens
    if (!existingUser.verified) {
      throw new UserNotVerifiedError(command.email);
    }

    const sanitizedUserDataForToken = this.commonAuthService.sanitizeForToken(existingUser, ['password']);

    const tokens: Tokens = await this.jwtService.generateTokens(sanitizedUserDataForToken, this.tokenConfig);

    return {
      success: true,
      message: AUTH_MESSAGES.TOKENS_GENERATED,
      tokens: tokens
    };
  }
}
