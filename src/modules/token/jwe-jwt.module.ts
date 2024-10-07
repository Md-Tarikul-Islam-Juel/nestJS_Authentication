import {Module} from '@nestjs/common';
import {JwtModule} from '@nestjs/jwt';
import {PassportModule} from '@nestjs/passport';
import {PrismaService} from 'src/modules/prisma/prisma.service';
import {JweJwtAccessTokenStrategy} from './strategy/jwe-jwt-access-token.strategy';
import {JweJwtRefreshTokenStrategy} from './strategy/jwe-jwt-refresh-token.strategy';
import {ConfigModule} from '@nestjs/config';
import tokenConfig from './config/token.config';

import {RedisModule} from '../redis/redis.module';
import {LoggerService} from '../logger/logger.service';
import {LoggerModule} from '../logger/logger.module';
import {LogoutTokenValidateService} from './service/logoutTokenValidateService.service';

@Module({
  imports: [
    ConfigModule.forRoot({
      load: [tokenConfig] // Load custom configuration
    }),
    PassportModule,
    JwtModule,
    RedisModule,
    LoggerModule
  ],
  providers: [JweJwtAccessTokenStrategy, JweJwtRefreshTokenStrategy, PrismaService, LogoutTokenValidateService, LoggerService],
  exports: [JwtModule, PassportModule, JweJwtAccessTokenStrategy, JweJwtRefreshTokenStrategy]
})
export class JwtConfigModule {}
