import {Injectable} from '@nestjs/common';
import {RedisService} from '../../../../platform/redis/redis.service';
import {OtpCachePort} from '../../domain/repositories/otp-cache.port';

/**
 * OTP Cache Implementation
 * Infrastructure adapter implementing OtpCachePort
 * Uses RedisService to cache OTP codes
 */
@Injectable()
export class OtpCacheAdapter implements OtpCachePort {
  constructor(private readonly redis: RedisService) {}

  async store(email: string, otp: string, ttlSeconds: number): Promise<void> {
    await this.redis.set(`otp:${email}`, otp, ttlSeconds);
  }

  async get(email: string): Promise<string | null> {
    return this.redis.get(`otp:${email}`);
  }

  async delete(email: string): Promise<void> {
    await this.redis.del(`otp:${email}`);
  }
}
