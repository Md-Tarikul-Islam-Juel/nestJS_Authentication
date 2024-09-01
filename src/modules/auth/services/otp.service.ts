import { Injectable, UnauthorizedException } from '@nestjs/common';
import * as otpGenerator from 'otp-generator';
import { PrismaService } from '../../prisma/prisma.service';
import { LoggerService } from '../../logger/logger.service';
import { invalidOrExpiredOTP } from '../utils/string';

@Injectable()
export class OtpService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly logger: LoggerService,
  ) {
  }

  generateOtp(length: number): string {
    return otpGenerator.generate(length, {
      digits: true,
      upperCase: false,
      lowercase: false,
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false,
    });
  }

  async storeOtp(email: string, otp: string, otpExpireTime: number): Promise<void> {
    const expiryTime: Date = new Date(Date.now() + otpExpireTime * 60 * 1000); // 10 minutes expiry

    await this.prisma.OTP.upsert({
      where: { email },
      update: { otp, expiresAt: expiryTime },
      create: { email, otp, expiresAt: expiryTime },
    });
  }

  async verifyOtp(email: string, otp: string): Promise<void> {
    const otpRecord = await this.prisma.OTP.findUnique({
      where: { email },
      select: { otp: true, expiresAt: true },
    });

    if (!otpRecord || otpRecord.otp !== otp || new Date() > otpRecord.expiresAt) {
      this.logger.error({
        message: `${invalidOrExpiredOTP}`,
        details: email,
      });
      throw new UnauthorizedException(invalidOrExpiredOTP);
    }
  }

  async deleteOtp(email: string) {
    return this.prisma.OTP.delete({ where: { email } });
  }
}
