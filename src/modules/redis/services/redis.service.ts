import {Injectable} from '@nestjs/common';
import Redis from 'ioredis';

@Injectable()
export class RedisService {
  private redisClient: Redis;

  constructor() {
    this.redisClient = new Redis({
      host: process.env.REDIS_HOST,
      port: Number(process.env.REDIS_PORT)
    });
  }

  async get(key: string): Promise<string | null> {
    return this.redisClient.get(key);
  }

  async set(key: string, value: string, expireInSec: number): Promise<void> {
    await this.redisClient.set(key, value, 'EX', expireInSec);
  }

  async del(key: string): Promise<void> {
    await this.redisClient.del(key);
  }

  // Fetch keys with a pattern (used in batch update)
  async keys(pattern: string): Promise<string[]> {
    return this.redisClient.keys(pattern);
  }
}
