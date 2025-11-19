import { Module } from '@nestjs/common';
import { APP_INTERCEPTOR, APP_GUARD } from '@nestjs/core';
// import {AppGraphqlModule} from './app-graphql.module'; // Commented out - no GraphQL resolvers defined
import { AppHttpModule } from './app-http.module';
import { LoggingInterceptor } from './common/http/interceptors/logging.interceptor';
import { VersionDeprecationInterceptor } from './common/http/interceptors/version-deprecation.interceptor';
import { LoggerModule } from './common/observability/logger.module';
import { SecurityModule } from './common/security/security.module';
import { ThrottlerBehindProxyGuard } from './common/guards/throttler-proxy.guard';
import { IPControlGuard } from './common/guards/ip-control.guard';
import { GeolocationGuard } from './common/guards/geolocation.guard';
import { DDoSProtectionGuard } from './common/guards/ddos-protection.guard';
import { ConfigModule } from './config/config.module';
import { PrismaModule } from './platform/prisma/prisma.module';
import { RedisModule } from './platform/redis/redis.module';
import { HealthModule } from './health/health.module';

@Module({
  imports: [ConfigModule, PrismaModule, RedisModule, LoggerModule, SecurityModule, AppHttpModule, HealthModule],
  providers: [
    {
      provide: APP_INTERCEPTOR,
      useClass: LoggingInterceptor
    },
    {
      provide: APP_INTERCEPTOR,
      useClass: VersionDeprecationInterceptor
    },
    {
      provide: APP_GUARD,
      useClass: ThrottlerBehindProxyGuard,
    },
    {
      provide: APP_GUARD,
      useClass: DDoSProtectionGuard,
    },
    {
      provide: APP_GUARD,
      useClass: IPControlGuard,
    },
    {
      provide: APP_GUARD,
      useClass: GeolocationGuard,
    },
  ]
})
export class AppModule { }
