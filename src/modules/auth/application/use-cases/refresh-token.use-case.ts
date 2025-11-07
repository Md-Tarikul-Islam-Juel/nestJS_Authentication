import {Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {PlatformJwtService, TokenConfig} from '../../../../platform/jwt/jwt.service';
import {AUTH_MESSAGES} from '../../../_shared/constants';
import {UserNotFoundError} from '../../domain/errors/user-not-found.error';
import {UserNotVerifiedError} from '../../domain/errors/user-not-verified.error';
import {CommonAuthService} from '../../domain/services/common-auth.service';
import {UserService} from '../../infrastructure/services/user.service';
import {RefreshTokenCommand} from '../commands/refresh-token.command';
import {Tokens} from '../dto/auth-base.dto';
import {RefreshTokenSuccessResponseDto} from '../dto/auth-response.dto';

@Injectable()
export class RefreshTokenUseCase {
  private readonly tokenConfig: TokenConfig;

  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UserService,
    private readonly jwtService: PlatformJwtService,
    private readonly commonAuthService: CommonAuthService
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

  async execute(command: RefreshTokenCommand): Promise<RefreshTokenSuccessResponseDto> {
    const existingUser = await this.userService.findUserByEmail(command.email);

    if (!existingUser) {
      throw new UserNotFoundError(command.email);
    }

    // Verify user is verified before generating new tokens
    if (!existingUser.verified) {
      throw new UserNotVerifiedError(command.email);
    }

    const sanitizedUserDataForToken = this.commonAuthService.removeSensitiveData(existingUser, ['password']);

    const tokens: Tokens = await this.jwtService.generateTokens(sanitizedUserDataForToken, this.tokenConfig);

    return {
      success: true,
      message: AUTH_MESSAGES.TOKENS_GENERATED,
      tokens: tokens
    };
  }
}
