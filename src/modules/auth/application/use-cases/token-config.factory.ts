import {ConfigService} from '@nestjs/config';
import type {TokenConfig} from '../../domain/repositories/jwt-service.port';

export function createTokenConfig(configService: ConfigService): TokenConfig {
  return {
    useJwe: configService.get<boolean>('authConfig.token.useJwe'),
    jweAccessTokenSecretKey: configService.get<string>('authConfig.token.jweAccessTokenSecretKey'),
    jwtAccessTokenSecretKey: configService.get<string>('authConfig.token.jwtAccessTokenSecretKey'),
    jweJwtAccessTokenExpireTime: configService.get<string>('authConfig.token.jweJwtAccessTokenExpireTime'),
    jweRefreshTokenSecretKey: configService.get<string>('authConfig.token.jweRefreshTokenSecretKey'),
    jwtRefreshTokenSecretKey: configService.get<string>('authConfig.token.jwtRefreshTokenSecretKey'),
    jweJwtRefreshTokenExpireTime: configService.get<string>('authConfig.token.jweJwtRefreshTokenExpireTime')
  };
}

