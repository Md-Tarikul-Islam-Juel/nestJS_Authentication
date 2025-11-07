import {Inject, Injectable} from '@nestjs/common';
import {Cron, CronExpression} from '@nestjs/schedule';
import {RedisService} from '../../../../platform/redis/redis.service';
import {USER_REPOSITORY_PORT} from '../../application/di-tokens';
import {UserRepositoryPort} from '../../domain/repositories/user.repository.port';

/**
 * Last Activity Track Service
 * Following Clean Architecture: all database queries go through repository
 */
@Injectable()
export class LastActivityTrackService {
  private readonly TTL = 30 * 60;
  private redisKey = 'trackLastActivity';

  constructor(
    private readonly redisService: RedisService,
    @Inject(USER_REPOSITORY_PORT)
    private readonly userRepository: UserRepositoryPort
  ) {}

  async updateLastActivityToRedis(userId: number): Promise<void> {
    const now = new Date().toISOString();
    await this.redisService.set(`${this.redisKey}:${userId}`, now, this.TTL);
  }

  async updateLastActivityInDB(userId: number): Promise<void> {
    try {
      // Following Clean Architecture: all database queries go through repository
      const user = await this.userRepository.findById(userId);

      if (!user) {
        // User not found or soft-deleted, skip update
        return;
      }

      const now = new Date();
      await Promise.race([
        this.userRepository.updateLastActivityAt(userId, now),
        new Promise((_, reject) => setTimeout(() => reject(new Error('Database timeout')), 5000))
      ]);
    } catch (error) {
      // Don't throw - last activity tracking is not critical for the main operation
      // Log error but don't fail the request
    }
  }

  @Cron(CronExpression.EVERY_10_MINUTES)
  async batchUpdateLastActivity(): Promise<void> {
    const keys = await this.redisService.keys(`${this.redisKey}:*`);

    for (const key of keys) {
      const userId = key.split(':')[1];
      const lastActiveTime = await this.redisService.get(key);

      if (lastActiveTime) {
        try {
          // Following Clean Architecture: all database queries go through repository
          const user = await this.userRepository.findById(parseInt(userId));

          if (user) {
            await this.userRepository.updateLastActivityAt(parseInt(userId), new Date(lastActiveTime));
          }

          // Delete key regardless of whether user exists (cleanup)
          await this.redisService.del(key);
        } catch (error) {
          // Skip failed updates, continue with next key
          continue;
        }
      }
    }
  }
}
