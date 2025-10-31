import {Module} from '@nestjs/common';
import {JwtModule} from '@nestjs/jwt';
import {PassportModule} from '@nestjs/passport';
import {LoggerModule} from '../../common/observability/logger.module';
import {PrismaModule} from '../../platform/prisma/prisma.module';
import {RedisModule} from '../../platform/redis/redis.module';
import {LogoutTokenValidateService} from './service/logoutTokenValidateService.service';
import {JweJwtAccessTokenStrategy} from './strategy/jwe-jwt-access-token.strategy';
import {JweJwtRefreshTokenStrategy} from './strategy/jwe-jwt-refresh-token.strategy';

@Module({
  imports: [PassportModule, JwtModule, PrismaModule, RedisModule, LoggerModule],
  providers: [JweJwtAccessTokenStrategy, JweJwtRefreshTokenStrategy, LogoutTokenValidateService],
  exports: [JwtModule, PassportModule, JweJwtAccessTokenStrategy, JweJwtRefreshTokenStrategy]
})
export class JwtConfigModule {}
