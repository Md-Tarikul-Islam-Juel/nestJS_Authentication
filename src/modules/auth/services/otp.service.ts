//
// import { Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
// import * as otpGenerator from 'otp-generator';
// import { LoggerService } from '../../logger/logger.service';
// import { RedisService } from '../../redis/services/redis.service';
// import { invalidOrExpiredOTP } from '../utils/string';
//
// @Injectable()
// export class OtpService {
//   constructor(
//     private readonly redisService: RedisService,
//     private readonly logger: LoggerService,
//   ) {}
//
//   /**
//    * Generate a one-time password (OTP)
//    * @param length - length of the OTP to generate
//    * @returns generated OTP string
//    */
//   generateOtp(length: number): string {
//     return otpGenerator.generate(length, {
//       digits: true,
//       upperCase: false,
//       lowercase: false,
//       upperCaseAlphabets: false,
//       lowerCaseAlphabets: false,
//       specialChars: false,
//     });
//   }
//
//   /**
//    * Store the OTP in Redis with an expiration time
//    * @param email - email address associated with the OTP
//    * @param otp - the generated OTP
//    * @param otpExpireTime - expiration time for the OTP in seconds
//    */
//   async storeOtp(
//     email: string,
//     otp: string,
//     otpExpireTime: number,
//   ): Promise<void> {
//     try {
//       await this.redisService.set(`otp:${email}`, otp, otpExpireTime * 60); // Store OTP with TTL in Redis
//       this.logger.info({
//         message: `OTP stored for email: ${email}`,
//         details: { otp, otpExpireTime },
//       });
//     } catch (error) {
//       this.logger.error({
//         message: 'Failed to store OTP in Redis',
//         details: error,
//       });
//     }
//   }
//
//   /**
//    * Verify the OTP from Redis
//    * @param email - email associated with the OTP
//    * @param otp - OTP to verify
//    * @throws UnauthorizedException if OTP is invalid or expired
//    */
//   async verifyOtp(email: string, otp: string): Promise<void> {
//     try {
//       const storedOtp = await this.redisService.get(`otp:${email}`); // Retrieve OTP from Redis
//       if (!storedOtp || storedOtp !== otp) {
//         this.logger.warn({
//           message: `Invalid or expired OTP for email: ${email}`,
//           details: { providedOtp: otp, storedOtp },
//         });
//
//         throw new UnauthorizedException(invalidOrExpiredOTP);
//       }
//       this.logger.info({
//         message: `OTP verified successfully for email: ${email}`,
//       });
//     } catch (error) {
//       this.logger.error({
//         message: 'Error during OTP verification',
//         details: error,
//       });
//     }
//   }
//
//   /**
//    * Delete the OTP from Redis after successful verification
//    * @param email - email associated with the OTP
//    */
//   async deleteOtp(email: string): Promise<void> {
//     try {
//       await this.redisService.del(`otp:${email}`); // Use the delete method to remove OTP from Redis
//       this.logger.info({ message: `OTP deleted for email: ${email}` });
//     } catch (error) {
//       this.logger.error({
//         message: 'Failed to delete OTP from Redis',
//         details: error,
//       });
//       throw new InternalServerErrorException('Failed to delete OTP');
//     }
//   }
// }

import {Injectable, InternalServerErrorException, UnauthorizedException} from '@nestjs/common';
import * as otpGenerator from 'otp-generator';
import {LoggerService} from '../../logger/logger.service';
import {RedisService} from '../../redis/services/redis.service';
import {PrismaService} from '../../prisma/prisma.service';
import {ConfigService} from '@nestjs/config';

@Injectable()
export class OtpService {
  private maxFailedAttempts: number; // Store the max failed attempts
  private lockoutTime: number; // Store the lockout time in minutes

  constructor(
    private readonly redisService: RedisService,
    private readonly prismaService: PrismaService,
    private readonly logger: LoggerService,
    private readonly configService: ConfigService
  ) {
    // Initialize values from the .env file
    this.maxFailedAttempts = this.configService.get<number>('OTP_MAX_FAILED_ATTEMPTS') || 5; // Default to 5 if not set
    this.lockoutTime = this.configService.get<number>('OTP_LOCKOUT_TIME') || 5; // Default to 5 minutes if not set
  }

  /**
   * Generate a one-time password (OTP)
   * @param length - length of the OTP to generate
   * @returns generated OTP string
   */
  generateOtp(length: number): string {
    return otpGenerator.generate(length, {
      digits: true,
      upperCase: false,
      lowercase: false,
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false
    });
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
