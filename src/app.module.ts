
import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { AuthModule } from './modules/auth/auth.module';
import { LoggerModule } from './modules/logger/logger.module';
import { PrismaModule } from './modules/prisma/prisma.module';
import { AllExceptionsFilter } from './modules/filter/all-exceptions.filter';
import { APP_FILTER } from '@nestjs/core';
import { UserModule } from './modules/user/user.module';
import { JwtConfigModule } from './modules/token/jwe-jwt.module';
import { RedisModule } from './modules/redis/redis.module';


@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    AuthModule,
    PrismaModule,
    LoggerModule,
    UserModule,
    JwtConfigModule,
    RedisModule,
  ],
  providers: [
    {
      provide: APP_FILTER,
      useClass: AllExceptionsFilter,
    },
  ],
})
export class AppModule {
}