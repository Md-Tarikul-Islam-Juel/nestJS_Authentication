import {forwardRef, Module} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {PrismaModule} from 'src/modules/prisma/prisma.module';
import {AuthController} from './controllers/auth.controller';
import {LoggerModule} from '../logger/logger.module';
import {AuthService} from './services/auth.service';
import {JwtConfigModule} from '../token/jwe-jwt.module';
import {JweJwtAccessTokenStrategy} from '../token/strategy/jwe-jwt-access-token.strategy';
import {JweJwtRefreshTokenStrategy} from '../token/strategy/jwe-jwt-refresh-token.strategy';
import {GoogleStrategy} from './strategys/google.strategy';
import {FacebookStrategy} from './strategys/facebook.strategy';
import {UserService} from './services/user.service';
import {OtpService} from './services/otp.service';
import {TokenService} from './services/token.service';
import {EmailService} from './services/email.service';
import {CommonAuthService} from './services/commonAuth.service';
import {PasswordService} from './services/password.service';
import {LoggerService} from '../logger/logger.service';
import {IsNotBlockedPassword} from './validators/password-validator.validator';
import {ConfigModule} from '@nestjs/config';
import {MailerModule} from '@nestjs-modules/mailer';
import authConfig from './config/auth.config';
import {RedisModule} from '../redis/redis.module';
import {LastActivityTrackService} from './services/lastActivityTrack.service';
import {ScheduleModule} from '@nestjs/schedule';
import {TrackLastActivityInterceptor} from './Interceptor/trackLastActivityInterceptor.interceptor';
import {APP_INTERCEPTOR} from '@nestjs/core';
import {LogoutService} from './services/logout.service';
import {LogoutTokenValidateService} from '../token/service/logoutTokenValidateService.service';

@Module({
  imports: [
    ScheduleModule.forRoot(), // for cron job
    ConfigModule.forRoot({
      load: [authConfig] // Load custom configuration
    }),
    MailerModule.forRootAsync({
      useFactory: async (config: ConfigService) => ({
        transport: {
          host: config.get<string>('authConfig.email.host'),
          port: config.get<number>('authConfig.email.port'),
          secure: false, // Set to true if using a secure connection
          auth: {
            user: config.get<string>('authConfig.email.email'),
            pass: config.get<string>('authConfig.email.pass')
          }
        }
      }),
      inject: [ConfigService]
    }),
    PrismaModule,
    LoggerModule,
    JwtConfigModule,
    RedisModule
  ],
  controllers: [AuthController],
  providers: [
    JweJwtAccessTokenStrategy,
    JweJwtRefreshTokenStrategy,
    GoogleStrategy,
    FacebookStrategy,
    AuthService,
    UserService,
    OtpService,
    TokenService,
    EmailService,
    PasswordService,
    CommonAuthService,
    LoggerService,
    IsNotBlockedPassword,
    LastActivityTrackService,
    LogoutService,
    LogoutTokenValidateService,
    {
      provide: APP_INTERCEPTOR,
      useClass: TrackLastActivityInterceptor
    }
  ],
  exports: [AuthService, LastActivityTrackService]
})
export class AuthModule {}
