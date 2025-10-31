import {Injectable} from '@nestjs/common';
import {Cron, CronExpression} from '@nestjs/schedule';
import {PrismaService} from '../../../../platform/prisma/prisma.service';
import {RedisService} from '../../../../platform/redis/redis.service';

@Injectable()
export class LastActivityTrackService {
  private readonly TTL = 30 * 60;
  private redisKey = 'trackLastActivity';

  constructor(
    private readonly redisService: RedisService,
    private readonly prisma: PrismaService
  ) {}

  async updateLastActivityToRedis(userId: number): Promise<void> {
    const now = new Date().toISOString();
    await this.redisService.set(`${this.redisKey}:${userId}`, now, this.TTL);
  }

  async updateLastActivityInDB(userId: number): Promise<void> {
    try {
      const now = new Date();
      await Promise.race([
        this.prisma.user.update({
          where: {id: userId},
          data: {lastActivityAt: now}
        }),
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
        await this.prisma.user.update({
          where: {id: parseInt(userId)},
          data: {lastActivityAt: new Date(lastActiveTime)}
        });

        await this.redisService.del(key);
      }
    }
  }
}
