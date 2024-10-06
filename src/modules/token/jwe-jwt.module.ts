import { Module} from '@nestjs/common';
import {JwtModule} from '@nestjs/jwt';
import {PassportModule} from '@nestjs/passport';
import {PrismaService} from 'src/modules/prisma/prisma.service';
import {JweJwtAccessTokenStrategy} from './jwe-jwt-access-token.strategy';
import {JweJwtRefreshTokenStrategy} from './jwe-jwt-refresh-token.strategy';
import {ConfigModule} from '@nestjs/config';
import tokenConfig from './config/token.config';

import {RedisModule} from '../redis/redis.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      load: [tokenConfig] // Load custom configuration
    }),
    PassportModule,
    JwtModule,
    RedisModule
  ],
  providers: [JweJwtAccessTokenStrategy, JweJwtRefreshTokenStrategy, PrismaService],
  exports: [JwtModule, PassportModule, JweJwtAccessTokenStrategy, JweJwtRefreshTokenStrategy]
})
export class JwtConfigModule {}
