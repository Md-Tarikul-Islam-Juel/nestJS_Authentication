import {Injectable} from '@nestjs/common';
import {RedisService} from '../../../../platform/redis/redis.service';
import {ActivityCachePort} from '../../domain/repositories/activity-cache.port';

/**
 * Activity Cache Adapter
 * Infrastructure adapter implementing ActivityCachePort
 * Uses RedisService to cache user activity data
 */
@Injectable()
export class ActivityCacheAdapter implements ActivityCachePort {
  constructor(private readonly redis: RedisService) {}

  async set(key: string, value: string, ttlSeconds: number): Promise<void> {
    await this.redis.set(key, value, ttlSeconds);
  }

  async get(key: string): Promise<string | null> {
    return this.redis.get(key);
  }

  async delete(key: string): Promise<void> {
    await this.redis.del(key);
  }

  async keys(pattern: string): Promise<string[]> {
    return this.redis.keys(pattern);
  }
}


