import {Module} from '@nestjs/common';
import {AppGraphqlModule} from './app-graphql.module';
import {AppHttpModule} from './app-http.module';
import {LoggerModule} from './common/observability/logger.module';
import {ConfigModule} from './config/config.module';
import {PrismaModule} from './platform/prisma/prisma.module';
import {RedisModule} from './platform/redis/redis.module';

@Module({
  imports: [ConfigModule, PrismaModule, RedisModule, LoggerModule, AppHttpModule, AppGraphqlModule]
})
export class AppModule {}
