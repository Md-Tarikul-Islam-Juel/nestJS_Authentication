import {Inject, Injectable, UnauthorizedException} from '@nestjs/common';
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
import {JtiProvider} from '../../../../platform/jwt/jti.provider';
import {JtiAllowlistService} from '../../../../platform/redis/jti-allowlist.service';

@Injectable()
export class RefreshTokenUseCase {
  private readonly tokenConfig: TokenConfig;

  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UserService,
    @Inject(JWT_SERVICE_PORT)
    private readonly jwtService: JwtServicePort,
    private readonly commonAuthService: CommonAuthService,
    private readonly jtiProvider: JtiProvider,
    private readonly jtiAllowlist: JtiAllowlistService
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

    // Rotate JTI: ensure presented jti matches allowlist, then swap to a new jti
    const refreshTtlSeconds = toSeconds(this.tokenConfig.jweJwtRefreshTokenExpireTime);
    const presentedSid = command.sid;
    const presentedJti = command.jti;
    if (!presentedSid || !presentedJti) {
      throw new UnauthorizedException('Invalid token');
    }
    const nextJti = this.jtiProvider.generateJti();

    const ok = await this.jtiAllowlist.rotateIfMatches(presentedSid, presentedJti, nextJti, refreshTtlSeconds);
    if (!ok) {
      throw new UnauthorizedException('Invalid token');
    }

    const tokens: Tokens = await this.jwtService.generateTokens(
      {...sanitizedUserDataForToken, sid: presentedSid, jti: nextJti},
      this.tokenConfig
    );

    return {
      success: true,
      message: AUTH_MESSAGES.TOKENS_GENERATED,
      tokens: tokens
    };
  }
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
