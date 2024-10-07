import {Injectable, InternalServerErrorException, UnauthorizedException} from '@nestjs/common';
import {LoggerService} from '../../logger/logger.service';
import {RedisService} from '../../redis/services/redis.service';
import {PrismaService} from '../../prisma/prisma.service';
import {ConfigService} from '@nestjs/config';
import {CommonAuthService} from './commonAuth.service';

@Injectable()
export class OtpService {
  private maxFailedAttempts: number; // Store the max failed attempts
  private lockoutTime: number; // Store the lockout time in minutes

  constructor(
    private readonly redisService: RedisService,
    private readonly prismaService: PrismaService,
    private readonly logger: LoggerService,
    private readonly configService: ConfigService,
    private readonly commonAuthService: CommonAuthService
  ) {
    // Initialize values from the .env file
    this.maxFailedAttempts = this.configService.get<number>('authConfig.otp.otpMaxFailedAttempts');
    this.lockoutTime = this.configService.get<number>('authConfig.otp.otpLockoutTime');
  }

  // Store OTP in Redis with TTL and throttle requests
  async storeOtp(email: string, otp: string, otpExpireTime: number): Promise<void> {
    try {
      // Store the OTP with a TTL in seconds
      await this.redisService.set(`otp:${email}`, otp, otpExpireTime * 60);
      this.logger.info({message: `OTP for ${email} stored successfully.`});
    } catch (error) {
      this.logger.error({
        message: `Failed to store OTP for ${email}.`,
        details: error
      });
      throw new InternalServerErrorException('Could not store OTP. Please try again.');
    }
  }

  // Verify the OTP from Redis
  async verifyOtp(email: string, otp: string): Promise<void> {
    const storedOtp = await this.redisService.get(`otp:${email}`);

    if (!storedOtp || storedOtp !== otp) {
      // Track failed attempts in the user record using Prisma
      await this.trackFailedOtpAttempts(email);

      this.logger.warn({message: `Invalid or expired OTP for ${email}.`});
      throw new UnauthorizedException('Invalid or expired OTP.');
    }

    // Clear OTP after successful verification
    await this.redisService.del(`otp:${email}`);
    await this.resetFailedOtpAttempts(email); // Reset failed attempts on successful OTP verification
    this.logger.info({message: `OTP for ${email} verified successfully.`});
  }

  // Track failed OTP attempts and lock the account if too many failed attempts
  async trackFailedOtpAttempts(email: string): Promise<void> {
    const user = await this.prismaService.user.findUnique({where: {email}});
    if (!user) throw new UnauthorizedException('User not found.');

    const attempts = user.failedOtpAttempts + 1;
    if (attempts >= this.maxFailedAttempts) {
      // Get lockout time in milliseconds
      const lockoutTimeInMs = this.lockoutTime * 60 * 1000;
      const lockoutUntil = new Date(Date.now() + lockoutTimeInMs); // Set the lockout expiration time

      await this.prismaService.user.update({
        where: {email},
        data: {
          failedOtpAttempts: attempts,
          accountLockedUntil: lockoutUntil
        }
      });
      throw new UnauthorizedException('Too many failed attempts. Your account is locked for 5 minutes.');
    } else {
      await this.prismaService.user.update({
        where: {email},
        data: {failedOtpAttempts: attempts}
      });
    }
  }

  // Reset failed OTP attempts after successful verification
  async resetFailedOtpAttempts(email: string): Promise<void> {
    await this.prismaService.user.update({
      where: {email},
      data: {failedOtpAttempts: 0, accountLockedUntil: null}
    });
  }

  /**
   * Delete the OTP from Redis after successful verification
   * @param email - email associated with the OTP
   */
  async deleteOtp(email: string): Promise<void> {
    try {
      await this.redisService.del(`otp:${email}`); // Use the delete method to remove OTP from Redis
      this.logger.info({message: `OTP deleted for email: ${email}`});
    } catch (error) {
      this.logger.error({
        message: 'Failed to delete OTP from Redis',
        details: error
      });
      throw new InternalServerErrorException('Failed to delete OTP');
    }
  }
}
