import {HttpException, HttpStatus, Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {AUTH_MESSAGES} from '../../../_shared/constants';
import {CommonAuthService} from '../../domain/services/common-auth.service';
import {TokenService} from '../../infrastructure/services/token.service';
import {UserService} from '../../infrastructure/services/user.service';
import {RefreshTokenCommand} from '../commands/refresh-token.command';
import {Tokens} from '../dto/auth-base.dto';
import {RefreshTokenSuccessResponseDto} from '../dto/auth-response.dto';
import {TokenConfig} from '../types/auth.types';

@Injectable()
export class RefreshTokenHandler {
  private readonly tokenConfig: TokenConfig;

  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UserService,
    private readonly tokenService: TokenService,
    private readonly commonAuthService: CommonAuthService
  ) {
    this.tokenConfig = {
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
      throw new HttpException(AUTH_MESSAGES.USER_NOT_FOUND, HttpStatus.NOT_FOUND);
    }

    const sanitizedUserDataForToken = this.commonAuthService.removeSensitiveData(existingUser, ['password']);

    const tokens: Tokens = await this.tokenService.generateTokens(sanitizedUserDataForToken, this.tokenConfig);

    return {
      success: true,
      message: AUTH_MESSAGES.TOKENS_GENERATED,
      tokens: tokens
    };
  }
}
