import { Module, Global } from '@nestjs/common';
import { ThrottlerModule } from '@nestjs/throttler';
import { ThrottlerStorageRedisService } from 'nestjs-throttler-storage-redis';
import { ConfigService } from '@nestjs/config';
import { RedisModule } from '../../platform/redis/redis.module';
import { IPControlService } from './ip-control.service';
import { GeolocationService } from './geolocation.service';
import { SSRFProtectionService } from './ssrf-protection.service';

/**
 * Security Module
 * Provides comprehensive security features:
 * - Rate limiting
 * - IP control (allowlist/blocklist)
 * - Geolocation-based access control
 * - SSRF Protection
 */
@Global()
@Module({
    imports: [
        RedisModule, // Import RedisModule to access RedisService
        ThrottlerModule.forRootAsync({
            inject: [ConfigService],
            useFactory: (config: ConfigService) => ({
                throttlers: [
                    {
                        name: 'default',
                        ttl: config.get<number>('THROTTLE_TTL') || 60000, // From .env
                        limit: config.get<number>('THROTTLE_LIMIT') || 100, // From .env
                    },
                ],
                storage: new ThrottlerStorageRedisService({
                    host: config.get('REDIS_HOST') || 'localhost',
                    port: config.get('REDIS_PORT') || 6379,
                }),
            }),
        }),
    ],
    providers: [
        IPControlService,
        GeolocationService,
        SSRFProtectionService,
    ],
    exports: [
        IPControlService,
        GeolocationService,
        SSRFProtectionService,
    ],
})
export class SecurityModule { }
