import {Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {LoggerService} from '../../../../common/observability/logger.service';
import {PrismaService} from '../../../../platform/prisma/prisma.service';
import {RedisService} from '../../../../platform/redis/redis.service';
import {AccountLockedError} from '../../domain/errors/account-locked.error';
import {CacheError} from '../../domain/errors/cache-error.error';
import {InvalidOtpError} from '../../domain/errors/invalid-otp.error';
import {UserNotFoundError} from '../../domain/errors/user-not-found.error';
import {CommonAuthService} from '../../domain/services/common-auth.service';

@Injectable()
export class OtpService {
  private maxFailedAttempts: number;
  private lockoutTime: number;

  constructor(
    private readonly redisService: RedisService,
    private readonly prismaService: PrismaService,
    private readonly logger: LoggerService,
    private readonly configService: ConfigService,
    private readonly commonAuthService: CommonAuthService
  ) {
    this.maxFailedAttempts = this.configService.get<number>('authConfig.otp.otpMaxFailedAttempts');
    this.lockoutTime = this.configService.get<number>('authConfig.otp.otpLockoutTime');
  }

  async storeOtp(email: string, otp: string, otpExpireTime: number): Promise<void> {
    try {
      await Promise.race([
        this.redisService.set(`otp:${email}`, otp, otpExpireTime * 60),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Redis timeout')), 5000))
      ]);
      this.logger.info({message: `OTP for ${email} stored successfully.`});
    } catch (error) {
      this.logger.error({
        message: 'Failed to store OTP in Redis',
        details: {
          email,
          error: error instanceof Error ? error.message : String(error)
        }
      });
      throw new CacheError('Failed to store OTP. Please try again.');
    }
  }

  async verifyOtp(email: string, otp: string): Promise<void> {
    const user = await this.prismaService.user.findUnique({where: {email}});

    if (!user) {
      throw new UserNotFoundError(email);
    }

    if (user.accountLockedUntil && new Date() < user.accountLockedUntil) {
      const remainingLockTime = Math.round((user.accountLockedUntil.getTime() - Date.now()) / 60000);
      throw new AccountLockedError(remainingLockTime);
    }

    const storedOtp = await this.redisService.get(`otp:${email}`);

    if (!storedOtp || storedOtp !== otp) {
      const failedAttempts = user.failedOtpAttempts + 1;

      if (failedAttempts >= this.maxFailedAttempts) {
        const lockoutUntil = new Date();
        lockoutUntil.setMinutes(lockoutUntil.getMinutes() + this.lockoutTime);

        await this.prismaService.user.update({
          where: {email},
          data: {
            failedOtpAttempts: failedAttempts,
            accountLockedUntil: lockoutUntil
          }
        });

        throw new AccountLockedError(this.lockoutTime);
      }

      await this.prismaService.user.update({
        where: {email},
        data: {failedOtpAttempts: failedAttempts}
      });

      throw new InvalidOtpError();
    }

    await this.prismaService.user.update({
      where: {email},
      data: {
        failedOtpAttempts: 0,
        accountLockedUntil: null
      }
    });
  }

  async deleteOtp(email: string): Promise<void> {
    try {
      await this.redisService.del(`otp:${email}`);
      this.logger.info({message: `OTP for ${email} deleted successfully.`});
    } catch (error) {
      this.logger.error({
        message: 'Failed to delete OTP from Redis',
        details: error
      });
    }
  }
}
