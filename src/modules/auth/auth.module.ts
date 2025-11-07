import {MailerModule} from '@nestjs-modules/mailer';
import {Module} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {APP_INTERCEPTOR} from '@nestjs/core';
import {ScheduleModule} from '@nestjs/schedule';
import {AccessTokenStrategy} from '../../common/auth/strategies/access-token.strategy';
import {LogoutTokenValidateService} from '../../common/auth/strategies/logout-token-validate.service';
import {RefreshTokenStrategy} from '../../common/auth/strategies/refresh-token.strategy';
import {LoggerModule} from '../../common/observability/logger.module';
import {PlatformJwtModule} from '../../platform/jwt/jwt.module';
import {PrismaModule} from '../../platform/prisma/prisma.module';
import {RedisModule} from '../../platform/redis/redis.module';
import {UNIT_OF_WORK_PORT} from '../../common/persistence/uow/di-tokens';
import {USER_REPOSITORY_PORT} from './application/di-tokens';
import {ChangePasswordUseCase} from './application/use-cases/change-password.use-case';
import {ForgetPasswordUseCase} from './application/use-cases/forget-password.use-case';
import {OAuthSignInUseCase} from './application/use-cases/oauth-sign-in.use-case';
import {RefreshTokenUseCase} from './application/use-cases/refresh-token.use-case';
import {RegisterUserUseCase} from './application/use-cases/register-user.use-case';
import {ResendOtpUseCase} from './application/use-cases/resend-otp.use-case';
import {SignInUseCase} from './application/use-cases/sign-in.use-case';
import {VerifyOtpUseCase} from './application/use-cases/verify-otp.use-case';
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
    PlatformJwtModule
  ],
  controllers: [AuthController],
  providers: [
    // Strategies
    AccessTokenStrategy,
    RefreshTokenStrategy,
    GoogleStrategy,
    FacebookStrategy,
    // Application Layer
    AuthService,
    // Application Use Cases
    RegisterUserUseCase,
    SignInUseCase,
    VerifyOtpUseCase,
    ResendOtpUseCase,
    ForgetPasswordUseCase,
    ChangePasswordUseCase,
    RefreshTokenUseCase,
    OAuthSignInUseCase,
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
