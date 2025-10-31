import {Inject, Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {LoggerService} from '../../../../common/observability/logger.service';
import {AUTH_MESSAGES} from '../../../_shared/constants';
import {LoginSource} from '../../domain/enums/login-source.enum';
import {EmailAlreadyExistsError} from '../../domain/errors/email-already-exists.error';
import {CommonAuthService} from '../../domain/services/common-auth.service';
import {OtpDomainService} from '../../domain/services/otp-domain.service';
import {PasswordPolicyService} from '../../domain/services/password-policy.service';
import {EmailService} from '../../infrastructure/email/email.service';
import {LastActivityTrackService} from '../../infrastructure/services/last-activity-track.service';
import {OtpService} from '../../infrastructure/services/otp.service';
import {UserService} from '../../infrastructure/services/user.service';
import {RegisterUserCommand} from '../commands/register-user.command';
import {UNIT_OF_WORK_PORT} from '../di-tokens';
import {SignupSuccessResponseDto} from '../dto/auth-response.dto';
import {UnitOfWorkPort} from '../uow/uow.port';

@Injectable()
export class RegisterUserHandler {
  private readonly saltRounds: number;
  private readonly otpExpireTime: number;

  constructor(
    private readonly configService: ConfigService,
    private readonly logger: LoggerService,
    private readonly userService: UserService,
    private readonly otpService: OtpService,
    private readonly passwordService: PasswordPolicyService,
    private readonly emailService: EmailService,
    private readonly commonAuthService: CommonAuthService,
    private readonly otpDomainService: OtpDomainService,
    private readonly lastActivityService: LastActivityTrackService,
    @Inject(UNIT_OF_WORK_PORT)
    private readonly uow: UnitOfWorkPort
  ) {
    this.saltRounds = this.configService.get<number>('authConfig.bcryptSaltRounds');
    this.otpExpireTime = this.configService.get<number>('authConfig.otp.otpExpireTime');
  }

  async execute(command: RegisterUserCommand): Promise<SignupSuccessResponseDto> {
    try {
      const existingUser = await this.userService.findUserByEmail(command.email);

      if (existingUser && existingUser.verified === true) {
        this.logger.error({
          message: AUTH_MESSAGES.USER_ALREADY_EXISTS,
          details: command
        });

        throw new EmailAlreadyExistsError(command.email);
      }

      const hashedPassword = await this.passwordService.hashPassword(command.password, this.saltRounds);

      const createdUser = await this.uow.withTransaction(async tx => {
        return await tx.user.upsert({
          where: {email: command.email},
          update: {
            email: command.email,
            firstName: command.firstName,
            lastName: command.lastName,
            loginSource: LoginSource.DEFAULT,
            verified: false,
            mfaEnabled: command.mfaEnabled || false
          },
          create: {
            email: command.email,
            password: hashedPassword,
            firstName: command.firstName,
            lastName: command.lastName,
            loginSource: LoginSource.DEFAULT,
            verified: false,
            mfaEnabled: command.mfaEnabled || false,
            isForgetPassword: false,
            logoutPin: ''
          }
        });
      });

      await this.sendOtp(createdUser.email);

      const sanitizedUserData = this.commonAuthService.removeSensitiveData(createdUser, [
        'password',
        'verified',
        'isForgetPassword',
        'mfaEnabled',
        'failedOtpAttempts',
        'logoutPin',
        'authorizerId',
        'loginSource',
        'lastActivityAt',
        'accountLockedUntil',
        'updatedAt'
      ]);

      await this.lastActivityService.updateLastActivityInDB(createdUser.id);

      return {
        success: true,
        message: `${AUTH_MESSAGES.SIGNUP_SUCCESSFUL} and please ${AUTH_MESSAGES.VERIFY_YOUR_USER}`,
        data: {
          user: sanitizedUserData as any,
          otp: {
            timeout: this.otpExpireTime,
            unit: 'mins'
          }
        }
      };
    } catch (error) {
      // Log error with full context
      this.logger.error({
        message: 'Error during user registration',
        details: {
          email: command.email,
          error: error instanceof Error ? error.message : String(error),
          stack: error instanceof Error ? error.stack : undefined
        }
      });

      // Re-throw domain errors and other exceptions to be handled by the filter
      throw error;
    }
  }

  private async sendOtp(email: string): Promise<void> {
    try {
      const otp = this.otpDomainService.generateOtp(6);

      // Try to store OTP - if it fails, log but don't block registration
      // User can resend OTP later
      try {
        await this.otpService.storeOtp(email, otp, this.otpExpireTime);
      } catch (otpStorageError) {
        this.logger.error({
          message: 'Failed to store OTP in Redis, but user registration succeeded',
          details: {
            email,
            error: otpStorageError instanceof Error ? otpStorageError.message : String(otpStorageError)
          }
        });
        // Don't throw - allow registration to succeed even if OTP storage fails
        // User can use resend OTP endpoint later
      }

      // Try to send email - if it fails, log but don't block registration
      try {
        await this.emailService.sendOtpEmail(email, otp, this.otpExpireTime);
      } catch (emailError) {
        this.logger.error({
          message: 'Failed to send OTP email, but user registration succeeded',
          details: {email, error: emailError instanceof Error ? emailError.message : String(emailError)}
        });
        // Don't throw - user is registered, email failure is not critical for signup
      }
    } catch (error) {
      // This catch block is for unexpected errors during OTP generation
      this.logger.error({
        message: 'Unexpected error during OTP generation',
        details: {email, error: error instanceof Error ? error.message : String(error)}
      });
      // Don't throw - allow registration to succeed, user can resend OTP
    }
  }
}
