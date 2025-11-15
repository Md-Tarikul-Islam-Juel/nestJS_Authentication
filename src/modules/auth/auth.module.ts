import {MailerModule} from '@nestjs-modules/mailer';
import {Module} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {APP_INTERCEPTOR} from '@nestjs/core';
import {ScheduleModule} from '@nestjs/schedule';
import {AccessTokenStrategy} from '../../common/auth/strategies/access-token.strategy';
import {LogoutTokenValidateService} from '../../common/auth/strategies/logout-token-validate.service';
import {RefreshTokenStrategy} from '../../common/auth/strategies/refresh-token.strategy';
import {LoggerModule} from '../../common/observability/logger.module';
import {UNIT_OF_WORK_PORT} from '../../common/persistence/uow/di-tokens';
import {PlatformJwtModule} from '../../platform/jwt/jwt.module';
import {PrismaModule} from '../../platform/prisma/prisma.module';
import {RedisModule} from '../../platform/redis/redis.module';
import {
  ACTIVITY_CACHE_PORT,
  EMAIL_SERVICE_PORT,
  JWT_SERVICE_PORT,
  LOGGER_PORT,
  OTP_CACHE_PORT,
  OTP_GENERATOR_PORT,
  PASSWORD_HASHER_PORT,
  USER_REPOSITORY_PORT
} from './application/di-tokens';
import {AuthService} from './application/services/auth.service';
import {CommonAuthService} from './application/services/common-auth.service';
import {LastActivityTrackService} from './application/services/last-activity-track.service';
import {LogoutService} from './application/services/logout.service';
import {OtpDomainService} from './application/services/otp-domain.service';
import {OtpService} from './application/services/otp.service';
import {PasswordPolicyService} from './application/services/password-policy.service';
import {PasswordValidationService} from './application/services/password-validation.service';
import {UserService} from './application/services/user.service';
import {ChangePasswordUseCase} from './application/use-cases/change-password.use-case';
import {ForgetPasswordUseCase} from './application/use-cases/forget-password.use-case';
import {OAuthSignInUseCase} from './application/use-cases/oauth-sign-in.use-case';
import {RefreshTokenUseCase} from './application/use-cases/refresh-token.use-case';
import {RegisterUserUseCase} from './application/use-cases/register-user.use-case';
import {ResendOtpUseCase} from './application/use-cases/resend-otp.use-case';
import {SignInUseCase} from './application/use-cases/sign-in.use-case';
import {VerifyOtpUseCase} from './application/use-cases/verify-otp.use-case';
import {ActivityCache} from './infrastructure/cache/activity.cache';
import {OtpCache} from './infrastructure/cache/otp.cache';
import {EmailService} from './infrastructure/email/email.service';
import {JwtAdapter} from './infrastructure/jwt/jwt.adapter';
import {OtpGeneratorAdapter} from './infrastructure/otp/otp-generator.adapter';
import {PasswordHasherAdapter} from './infrastructure/password/password-hasher.adapter';
import {FacebookStrategy} from './infrastructure/oauth-strategies/facebook.strategy';
import {GoogleStrategy} from './infrastructure/oauth-strategies/google.strategy';
import {LoggerAdapter} from './infrastructure/observability/logger.adapter';
import {UserPrismaRepository} from './infrastructure/prisma/user.prisma.repository';
import {PrismaUnitOfWork} from './infrastructure/uow/prisma.uow';
import {AuthController} from './interface/http/auth.controller';
import {TrackLastActivityInterceptor} from './interface/http/interceptors/track-last-activity.interceptor';
import {PasswordValidator} from './interface/validators/password-validator.class';

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
    CommonAuthService,
    LastActivityTrackService,
    LogoutService,
    OtpDomainService,
    OtpService,
    PasswordPolicyService,
    PasswordValidationService,
    UserService,
    // Application Use Cases
    RegisterUserUseCase,
    SignInUseCase,
    VerifyOtpUseCase,
    ResendOtpUseCase,
    ForgetPasswordUseCase,
    ChangePasswordUseCase,
    RefreshTokenUseCase,
    OAuthSignInUseCase,
    // Infrastructure Services
    {
      provide: USER_REPOSITORY_PORT,
      useClass: UserPrismaRepository
    },
    UserPrismaRepository,
    {
      provide: EMAIL_SERVICE_PORT,
      useClass: EmailService
    },
    EmailService,
    {
      provide: OTP_CACHE_PORT,
      useClass: OtpCache
    },
    OtpCache,
    {
      provide: ACTIVITY_CACHE_PORT,
      useClass: ActivityCache
    },
    ActivityCache,
    {
      provide: JWT_SERVICE_PORT,
      useClass: JwtAdapter
    },
    JwtAdapter,
    {
      provide: LOGGER_PORT,
      useClass: LoggerAdapter
    },
    LoggerAdapter,
    {
      provide: PASSWORD_HASHER_PORT,
      useClass: PasswordHasherAdapter
    },
    PasswordHasherAdapter,
    {
      provide: OTP_GENERATOR_PORT,
      useClass: OtpGeneratorAdapter
    },
    OtpGeneratorAdapter,
    LastActivityTrackService,
    LogoutService,
    {
      provide: UNIT_OF_WORK_PORT,
      useClass: PrismaUnitOfWork
    },
    PrismaUnitOfWork,
    // Validators
    PasswordValidator,
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
