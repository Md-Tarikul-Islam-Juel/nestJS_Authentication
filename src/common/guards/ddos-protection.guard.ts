import { Injectable, CanActivate, ExecutionContext, HttpException, HttpStatus } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ConfigService } from '@nestjs/config';
import { RedisService } from '../../platform/redis/redis.service';
import { LoggerService } from '../observability/logger.service';

export const SKIP_DDOS_CHECK_KEY = 'skipDdosCheck';

/**
 * DDoS Protection Guard
 * Protects against distributed denial of service attacks
 * Configuration from .env:
 * - DDOS_MAX_REQUESTS
 * - DDOS_WINDOW_SIZE
 * - DDOS_BLOCK_DURATION
 */
@Injectable()
export class DDoSProtectionGuard implements CanActivate {
    private readonly WINDOW_SIZE: number;
    private readonly MAX_REQUESTS: number;
    private readonly BLOCK_DURATION: number;

    constructor(
        private readonly redis: RedisService,
        private readonly logger: LoggerService,
        private readonly reflector: Reflector,
        private readonly config: ConfigService,
    ) {
        this.MAX_REQUESTS = this.config.get<number>('DDOS_MAX_REQUESTS') || 1000;
        this.WINDOW_SIZE = this.config.get<number>('DDOS_WINDOW_SIZE') || 60;
        this.BLOCK_DURATION = this.config.get<number>('DDOS_BLOCK_DURATION') || 3600;
    }

    async canActivate(context: ExecutionContext): Promise<boolean> {
        // Check if DDoS check should be skipped for this route
        const skipDdosCheck = this.reflector.getAllAndOverride<boolean>(SKIP_DDOS_CHECK_KEY, [
            context.getHandler(),
            context.getClass(),
        ]);

        if (skipDdosCheck) {
            return true;
        }

        const request = context.switchToHttp().getRequest();
        const ip = this.extractIP(request);

        // Check if IP is already blocked
        const isBlocked = await this.redis.get(`ddos:blocked:${ip}`);
        if (isBlocked) {
            this.logger.warn({
                message: 'DDoS blocked IP attempted access',
                details: { ip },
            });
            throw new HttpException(
                'Too many requests - IP temporarily blocked',
                HttpStatus.TOO_MANY_REQUESTS,
            );
        }

        // Count requests
        const key = `ddos:count:${ip}`;
        const count = await this.redis.incr(key);

        if (count === 1) {
            await this.redis.expire(key, this.WINDOW_SIZE);
        }

        // Block if threshold exceeded
        if (count > this.MAX_REQUESTS) {
            await this.redis.set(`ddos:blocked:${ip}`, '1', this.BLOCK_DURATION);

            this.logger.error({
                message: 'DDoS attack detected - IP blocked',
                details: {
                    ip,
                    requestCount: count,
                    blockDuration: this.BLOCK_DURATION,
                },
            });

            throw new HttpException(
                'Too many requests - IP blocked for 1 hour',
                HttpStatus.TOO_MANY_REQUESTS,
            );
        }

        // Warn if approaching limit
        if (count > this.MAX_REQUESTS * 0.8) {
            this.logger.warn({
                message: 'High request rate detected',
                details: { ip, requestCount: count },
            });
        }

        return true;
    }

    private extractIP(request: any): string {
        const forwardedFor = request.headers['x-forwarded-for'];
        if (forwardedFor) {
            return forwardedFor.split(',')[0].trim();
        }
        return request.ip || 'unknown';
    }
}
