import { Inject, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { AccountLockedError } from '../../domain/errors/account-locked.error';
import { CacheError } from '../../domain/errors/cache-error.error';
import { InvalidOtpError } from '../../domain/errors/invalid-otp.error';
import { UserNotFoundError } from '../../domain/errors/user-not-found.error';
import type { LoggerPort } from '../../domain/repositories/logger.port';
import type { OtpCachePort } from '../../domain/repositories/otp-cache.port';
import type { UserRepositoryPort } from '../../domain/repositories/user.repository.port';
import { LOGGER_PORT, OTP_CACHE_PORT, USER_REPOSITORY_PORT } from '../di-tokens';
import { CommonAuthService } from './common-auth.service';

/**
 * OTP Service
 * Application layer service for OTP operations
 * Following Clean Architecture: all database queries go through repository
 */
@Injectable()
export class OtpService {
  private maxFailedAttempts: number;
  private lockoutTime: number;

  constructor(
    @Inject(OTP_CACHE_PORT)
    private readonly otpCache: OtpCachePort,
    @Inject(USER_REPOSITORY_PORT)
    private readonly userRepository: UserRepositoryPort,
    @Inject(LOGGER_PORT)
    private readonly logger: LoggerPort,
    private readonly configService: ConfigService,
    private readonly commonAuthService: CommonAuthService
  ) {
    this.maxFailedAttempts = this.configService.get<number>('authConfig.otp.otpMaxFailedAttempts') ?? 5;
    this.lockoutTime = this.configService.get<number>('authConfig.otp.otpLockoutTime') ?? 5;
  }

  async storeOtp(email: string, otp: string, otpExpireTime: number): Promise<void> {
    try {
      await Promise.race([
        this.otpCache.store(email, otp, otpExpireTime * 60),
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
    // Following Clean Architecture: all database queries go through repository
    const user = await this.userRepository.findByEmailString(email);

    if (!user) {
      throw new UserNotFoundError(email);
    }

    if (user.accountLockedUntil && new Date() < user.accountLockedUntil) {
      const remainingLockTime = Math.round((user.accountLockedUntil.getTime() - Date.now()) / 60000);
      throw new AccountLockedError(remainingLockTime);
    }

    const storedOtp = await this.otpCache.get(email);

    if (!storedOtp || storedOtp !== otp) {
      const failedAttempts = user.failedOtpAttempts + 1;

      if (failedAttempts >= this.maxFailedAttempts) {
        const lockoutUntil = new Date();
        lockoutUntil.setMinutes(lockoutUntil.getMinutes() + this.lockoutTime);

        await this.userRepository.updateOtpAttempts(user.id, failedAttempts, lockoutUntil);

        throw new AccountLockedError(this.lockoutTime);
      }

      await this.userRepository.updateOtpAttempts(user.id, failedAttempts, null);

      throw new InvalidOtpError();
    }

    // Reset OTP attempts on successful verification
    await this.userRepository.updateOtpAttempts(user.id, 0, null);
  }

  async deleteOtp(email: string): Promise<void> {
    try {
      await this.otpCache.delete(email);
      this.logger.info({message: `OTP for ${email} deleted successfully.`});
    } catch (error) {
      this.logger.error({
        message: 'Failed to delete OTP from Redis',
        details: error
      });
    }
  }
}
