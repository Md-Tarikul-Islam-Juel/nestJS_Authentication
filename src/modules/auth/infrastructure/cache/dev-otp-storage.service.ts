import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { RedisService } from '../../../../platform/redis/redis.service';

/**
 * Development OTP Storage Service
 * Stores OTPs in Redis for viewing in development mode
 * ONLY used in development environment
 */
@Injectable()
export class DevOtpStorageService {
  private readonly DEV_OTP_PREFIX = 'dev:otp:';
  private readonly isEnabled: boolean;

  constructor(
    private readonly redisService: RedisService,
    private readonly configService: ConfigService
  ) {
    const nodeEnv = this.configService.get<string>('NODE_ENV', 'development');
    this.isEnabled = nodeEnv === 'development';
  }

  /**
   * Store OTP for development viewing
   */
  async storeOtp(email: string, otp: string, expirationMinutes: number): Promise<void> {
    if (!this.isEnabled) {
      return; // Skip in production
    }

    const key = `${this.DEV_OTP_PREFIX}${email}`;
    const data = {
      email,
      otp,
      createdAt: new Date().toISOString(),
      expiresAt: new Date(Date.now() + expirationMinutes * 60 * 1000).toISOString()
    };

    await this.redisService.set(key, JSON.stringify(data), expirationMinutes * 60);
  }

  /**
   * Get all stored OTPs
   */
  async getAllOtps(): Promise<Array<{email: string; otp: string; createdAt: string; expiresAt: string}>> {
    if (!this.isEnabled) {
      return [];
    }

    const keys = await this.redisService.keys(`${this.DEV_OTP_PREFIX}*`);
    const otps = [];

    for (const key of keys) {
      const data = await this.redisService.get(key);
      if (data) {
        try {
          otps.push(JSON.parse(data));
        } catch (error) {
          // Skip invalid JSON
        }
      }
    }

    // Sort by creation time, newest first
    return otps.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
  }

  /**
   * Clear all OTPs
   */
  async clearAll(): Promise<void> {
    if (!this.isEnabled) {
      return;
    }

    const keys = await this.redisService.keys(`${this.DEV_OTP_PREFIX}*`);
    for (const key of keys) {
      await this.redisService.del(key);
    }
  }
}
