import {Injectable} from '@nestjs/common';
import {Cron, CronExpression} from '@nestjs/schedule';
import {PrismaService} from '../../prisma/prisma.service';
import {RedisService} from '../../redis/services/redis.service';

@Injectable()
export class LastActivityTrackService {
  private readonly TTL = 30 * 60; // 30 min TTL
  private redisKey = 'trackLastActivity';

  constructor(
    private readonly redisService: RedisService,
    private readonly prisma: PrismaService
  ) {}

  // Log user activity in Redis
  async updateLastActivityToRedis(userId: number) {
    const now = new Date().toISOString();
    await this.redisService.set(`${this.redisKey}:${userId}`, now, this.TTL);
  }

  // Directly update lastActivityAt in the database
  async updateLastActivityInDB(userId: number) {
    const now = new Date();
    await this.prisma.user.update({
      where: {id: userId},
      data: {lastActivityAt: now}
    });
  }

  @Cron(CronExpression.EVERY_10_MINUTES)// Cron job to run every 10 minutes
  // @Cron('*/1 * * * *') // Cron job to run every 1 minute
  async batchUpdateLastActivity() {
    // Fetch all keys matching 'lastActivity:*'
    const keys = await this.redisService.keys(`${this.redisKey}:*`);

    for (const key of keys) {
      const userId = key.split(':')[1]; // Extract user ID from the key
      const lastActiveTime = await this.redisService.get(key);

      if (lastActiveTime) {
        // Update lastActivityAt in the database
        await this.prisma.user.update({
          where: {id: parseInt(userId)},
          data: {lastActivityAt: new Date(lastActiveTime)}
        });

        // Optionally, delete the Redis key after updating
        await this.redisService.del(key);
      }
    }
  }
}
