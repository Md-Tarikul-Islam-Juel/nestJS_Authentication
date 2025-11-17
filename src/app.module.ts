import {Module} from '@nestjs/common';
import {APP_INTERCEPTOR} from '@nestjs/core';
import {AppGraphqlModule} from './app-graphql.module';
import {AppHttpModule} from './app-http.module';
import {LoggingInterceptor} from './common/http/interceptors/logging.interceptor';
import {VersionDeprecationInterceptor} from './common/http/interceptors/version-deprecation.interceptor';
import {LoggerModule} from './common/observability/logger.module';
import {ConfigModule} from './config/config.module';
import {PrismaModule} from './platform/prisma/prisma.module';
import {RedisModule} from './platform/redis/redis.module';

@Module({
  imports: [ConfigModule, PrismaModule, RedisModule, LoggerModule, AppHttpModule, AppGraphqlModule],
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: LoggingInterceptor
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: VersionDeprecationInterceptor
    }
  ]
})
export class AppModule {}
