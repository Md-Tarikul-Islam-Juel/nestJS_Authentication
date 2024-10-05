import { Module } from '@nestjs/common';
import { RedisService } from './services/redis.service';

@Module({
  imports: [],
  controllers: [],
  providers: [
    RedisService
  ],
  exports: [RedisService],
})
export class RedisModule {}
