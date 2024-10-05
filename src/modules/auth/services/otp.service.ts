// import { Injectable, UnauthorizedException } from '@nestjs/common';
// import * as otpGenerator from 'otp-generator';
// import { PrismaService } from '../../prisma/prisma.service';
// import { LoggerService } from '../../logger/logger.service';
// import { invalidOrExpiredOTP } from '../utils/string';
//
// @Injectable()
// export class OtpService {
//   constructor(
//     private readonly prisma: PrismaService,
//     private readonly logger: LoggerService,
//   ) {
//   }
//
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
//   async storeOtp(email: string, otp: string, otpExpireTime: number): Promise<void> {
//     const expiryTime: Date = new Date(Date.now() + otpExpireTime * 60 * 1000); // 10 minutes expiry
//
//     await this.prisma.OTP.upsert({
//       where: { email },
//       update: { otp, expiresAt: expiryTime },
//       create: { email, otp, expiresAt: expiryTime },
//     });
//   }
//
//   async verifyOtp(email: string, otp: string): Promise<void> {
//     const otpRecord = await this.prisma.OTP.findUnique({
//       where: { email },
//       select: { otp: true, expiresAt: true },
//     });
//
//     if (!otpRecord || otpRecord.otp !== otp || new Date() > otpRecord.expiresAt) {
//       this.logger.error({
//         message: `${invalidOrExpiredOTP}`,
//         details: email,
//       });
//       throw new UnauthorizedException(invalidOrExpiredOTP);
//     }
//   }
//
//   async deleteOtp(email: string) {
//     return this.prisma.OTP.delete({ where: { email } });
//   }
// }

import { Injectable, InternalServerErrorException, UnauthorizedException } from '@nestjs/common';
import * as otpGenerator from 'otp-generator';
import { LoggerService } from '../../logger/logger.service';
import { RedisService } from '../../redis/services/redis.service';
import { invalidOrExpiredOTP } from '../utils/string';

@Injectable()
export class OtpService {
  constructor(
    private readonly redisService: RedisService,
    private readonly logger: LoggerService,
  ) {}

  /**
   * Generate a one-time password (OTP)
   * @param length - length of the OTP to generate
   * @returns generated OTP string
   */
  generateOtp(length: number): string {
    try {
      const otp = otpGenerator.generate(length, {
        digits: true,
        upperCase: false,
        lowercase: false,
        upperCaseAlphabets: false,
        lowerCaseAlphabets: false,
        specialChars: false,
      });
      this.logger.info({
        message: 'OTP generated successfully',
        details: { otp },
      });
      return otp;
    } catch (error) {
      this.logger.error({ message: 'Failed to generate OTP', details: error });
    }
  }

  /**
   * Store the OTP in Redis with an expiration time
   * @param email - email address associated with the OTP
   * @param otp - the generated OTP
   * @param otpExpireTime - expiration time for the OTP in seconds
   */
  async storeOtp(
    email: string,
    otp: string,
    otpExpireTime: number,
  ): Promise<void> {
    try {
      await this.redisService.set(`otp:${email}`, otp, otpExpireTime * 60); // Store OTP with TTL in Redis
      this.logger.info({
        message: `OTP stored for email: ${email}`,
        details: { otp, otpExpireTime },
      });
    } catch (error) {
      this.logger.error({
        message: 'Failed to store OTP in Redis',
        details: error,
      });
    }
  }

  /**
   * Verify the OTP from Redis
   * @param email - email associated with the OTP
   * @param otp - OTP to verify
   * @throws UnauthorizedException if OTP is invalid or expired
   */
  async verifyOtp(email: string, otp: string): Promise<void> {
    try {
      const storedOtp = await this.redisService.get(`otp:${email}`); // Retrieve OTP from Redis
      if (!storedOtp || storedOtp !== otp) {
        this.logger.warn({
          message: `Invalid or expired OTP for email: ${email}`,
          details: { providedOtp: otp, storedOtp },
        });

        throw new UnauthorizedException(invalidOrExpiredOTP);
      }
      this.logger.info({
        message: `OTP verified successfully for email: ${email}`,
      });
    } catch (error) {
      this.logger.error({
        message: 'Error during OTP verification',
        details: error,
      });
    }
  }

  /**
   * Delete the OTP from Redis after successful verification
   * @param email - email associated with the OTP
   */
  async deleteOtp(email: string): Promise<void> {
    try {
      await this.redisService.del(`otp:${email}`); // Use the delete method to remove OTP from Redis
      this.logger.info({ message: `OTP deleted for email: ${email}` });
    } catch (error) {
      this.logger.error({
        message: 'Failed to delete OTP from Redis',
        details: error,
      });
      throw new InternalServerErrorException('Failed to delete OTP');
    }
  }
}
