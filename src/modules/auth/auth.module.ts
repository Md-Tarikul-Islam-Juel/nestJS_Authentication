import {MailerModule} from '@nestjs-modules/mailer';
import {Module} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {APP_INTERCEPTOR} from '@nestjs/core';
import {ScheduleModule} from '@nestjs/schedule';
import {LoggerModule} from '../../common/observability/logger.module';
import {PrismaModule} from '../../platform/prisma/prisma.module';
import {RedisModule} from '../../platform/redis/redis.module';
import {JwtConfigModule} from '../token/jwe-jwt.module';
import {LogoutTokenValidateService} from '../token/service/logoutTokenValidateService.service';
import {JweJwtAccessTokenStrategy} from '../token/strategy/jwe-jwt-access-token.strategy';
import {JweJwtRefreshTokenStrategy} from '../token/strategy/jwe-jwt-refresh-token.strategy';
import {UNIT_OF_WORK_PORT, USER_REPOSITORY_PORT} from './application/di-tokens';
import {ChangePasswordHandler} from './application/handlers/change-password.handler';
import {ForgetPasswordHandler} from './application/handlers/forget-password.handler';
import {OAuthSignInHandler} from './application/handlers/oauth-sign-in.handler';
import {RefreshTokenHandler} from './application/handlers/refresh-token.handler';
import {RegisterUserHandler} from './application/handlers/register-user.handler';
import {ResendOtpHandler} from './application/handlers/resend-otp.handler';
import {SignInHandler} from './application/handlers/sign-in.handler';
import {VerifyOtpHandler} from './application/handlers/verify-otp.handler';
import {AuthService} from './application/services/auth.service';
import {CommonAuthService} from './domain/services/common-auth.service';
import {OtpDomainService} from './domain/services/otp-domain.service';
import {PasswordPolicyService} from './domain/services/password-policy.service';
import {FacebookStrategy} from './infrastructure/auth/facebook.strategy';
import {GoogleStrategy} from './infrastructure/auth/google.strategy';
import {OtpCache} from './infrastructure/cache/otp.cache';
import {EmailService} from './infrastructure/email/email.service';
import {UserPrismaRepository} from './infrastructure/prisma/user.prisma.repository';
import {LastActivityTrackService} from './infrastructure/services/last-activity-track.service';
import {LogoutService} from './infrastructure/services/logout.service';
import {OtpService} from './infrastructure/services/otp.service';
import {TokenService} from './infrastructure/services/token.service';
import {UserService} from './infrastructure/services/user.service';
import {PrismaUnitOfWork} from './infrastructure/uow/prisma.uow';
import {AuthController} from './interface/http/auth.controller';
import {TrackLastActivityInterceptor} from './interface/http/interceptors/track-last-activity.interceptor';
import {IsNotBlockedPassword} from './interface/validators/password-validator.validator';

@Module({
  imports: [
    ScheduleModule.forRoot(),
    MailerModule.forRootAsync({
      useFactory: async (config: ConfigService) => ({
        transport: {
          host: config.get<string>('authConfig.email.host'),
          port: config.get<number>('authConfig.email.port'),
          secure: false,
          auth: {
            user: config.get<string>('authConfig.email.email'),
            pass: config.get<string>('authConfig.email.pass')
          }
        }
      }),
      inject: [ConfigService]
    }),
    PrismaModule,
    RedisModule,
    LoggerModule,
    JwtConfigModule
  ],
  controllers: [AuthController],
  providers: [
    // Strategies
    JweJwtAccessTokenStrategy,
    JweJwtRefreshTokenStrategy,
    GoogleStrategy,
    FacebookStrategy,
    // Application Layer
    AuthService,
    // Command Handlers
    RegisterUserHandler,
    SignInHandler,
    VerifyOtpHandler,
    ResendOtpHandler,
    ForgetPasswordHandler,
    ChangePasswordHandler,
    RefreshTokenHandler,
    OAuthSignInHandler,
    // Domain Services
    PasswordPolicyService,
    OtpDomainService,
    // Infrastructure Services
    {
      provide: USER_REPOSITORY_PORT,
      useClass: UserPrismaRepository
    },
    UserPrismaRepository,
    OtpCache,
    EmailService,
    LastActivityTrackService,
    LogoutService,
    {
      provide: UNIT_OF_WORK_PORT,
      useClass: PrismaUnitOfWork
    },
    PrismaUnitOfWork,
    // Legacy services (to be refactored)
    TokenService,
    UserService,
    OtpService,
    CommonAuthService,
    // Validators
    IsNotBlockedPassword,
    // Token validation
    LogoutTokenValidateService,
    // Interceptors
    {
      provide: APP_INTERCEPTOR,
      useClass: TrackLastActivityInterceptor
    }
  ],
  exports: [AuthService, LastActivityTrackService]
})
export class AuthModule {}
