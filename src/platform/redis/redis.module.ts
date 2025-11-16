import {Module} from '@nestjs/common';
import {ConfigModule} from '@nestjs/config';
import {RedisService} from './redis.service';
import {JtiAllowlistService} from './jti-allowlist.service';
import {UserSessionIndexService} from './user-session-index.service';

@Module({
  imports: [ConfigModule],
  providers: [RedisService, JtiAllowlistService, UserSessionIndexService],
  exports: [RedisService, JtiAllowlistService, UserSessionIndexService]
})
export class RedisModule {}
