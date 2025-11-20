import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { RedisModule } from '../../platform/redis/redis.module';
import { DevOtpStorageService } from '../auth/infrastructure/cache/dev-otp-storage.service';
import { DevOtpViewerController } from './dev-otp-viewer.controller';

/**
 * Development Module
 * Contains development-only features like OTP viewer
 * Should only be imported in development environment
 */
@Module({
  imports: [ConfigModule, RedisModule],
  controllers: [DevOtpViewerController],
  providers: [DevOtpStorageService],
  exports: [DevOtpStorageService]
})
export class DevModule {}
