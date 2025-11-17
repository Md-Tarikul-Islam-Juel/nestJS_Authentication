import {Request, Response, NextFunction} from 'express';
import {LoggerService} from '../observability/logger.service';
import {RedisService} from '../../platform/redis/redis.service';

export interface AdaptiveRateLimiterOptions {
  keyPrefix: string;
  windowMs: number;
  maxRequests: number;
  blockDurationMs: number;
  identifierExtractor?: (req: Request) => string[];
  blockResponseMessage?: string;
}

const DEFAULT_RATE_LIMITER_OPTIONS: AdaptiveRateLimiterOptions = {
  keyPrefix: 'rate-limit',
  windowMs: 60_000,
  maxRequests: 50,
  blockDurationMs: 15 * 60_000,
  blockResponseMessage: 'Too many requests, please try again later.'
};

const DEFAULT_WINDOW_SECONDS = Math.ceil(DEFAULT_RATE_LIMITER_OPTIONS.windowMs / 1000);

function defaultIdentifierExtractor(req: Request): string[] {
  const identifiers: string[] = [];
  const forwardedIp = Array.isArray(req.headers['x-forwarded-for'])
    ? req.headers['x-forwarded-for'][0]
    : req.headers['x-forwarded-for'];
  const ip = forwardedIp?.split(',')[0]?.trim() || req.ip || req.socket.remoteAddress || 'unknown';
  identifiers.push(`ip:${ip}`);

  if (typeof req.body?.email === 'string') {
    identifiers.push(`email:${req.body.email.toLowerCase()}`);
  }

  const userId = (req as any)?.user?.id;
  if (userId) {
    identifiers.push(`user:${userId}`);
  }

  return identifiers;
}

function buildRedisKey(prefix: string, identifiers: string[]): string {
  return `${prefix}:${identifiers.join('|')}`;
}

export function createAdaptiveRateLimiter(
  redisService: RedisService,
  logger: LoggerService,
  options?: Partial<AdaptiveRateLimiterOptions>
): (req: Request, res: Response, next: NextFunction) => Promise<void> {
  const config: AdaptiveRateLimiterOptions = {
    ...DEFAULT_RATE_LIMITER_OPTIONS,
    ...options
  };

  const identifierResolver = config.identifierExtractor ?? defaultIdentifierExtractor;
  const windowSeconds = Math.ceil(config.windowMs / 1000) || DEFAULT_WINDOW_SECONDS;
  const blockSeconds = Math.ceil(config.blockDurationMs / 1000);

  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    try {
      const identifiers = identifierResolver(req);
      if (identifiers.length === 0) {
        identifiers.push('unknown');
      }

      const key = buildRedisKey(config.keyPrefix, identifiers);
      const blockKey = `${key}:blocked`;

      const existingBlockTtl = await redisService.ttl(blockKey);
      if (existingBlockTtl && existingBlockTtl > 0) {
        const retryAfter = existingBlockTtl;
        res.setHeader('Retry-After', retryAfter.toString());
        res.status(429).json({
          success: false,
          message: config.blockResponseMessage,
          retryAfterSeconds: retryAfter
        });
        return;
      }

      const currentCount = await redisService.increment(key, windowSeconds);

      const windowTtl = await redisService.ttl(key);
      const remaining = Math.max(config.maxRequests - currentCount, 0);
      const resetSeconds = windowTtl ?? windowSeconds;

      res.setHeader('RateLimit-Limit', config.maxRequests.toString());
      res.setHeader('RateLimit-Remaining', Math.max(remaining, 0).toString());
      res.setHeader('RateLimit-Reset', Math.max(resetSeconds, 0).toString());
      res.setHeader('X-RateLimit-Limit', config.maxRequests.toString());
      res.setHeader('X-RateLimit-Remaining', Math.max(remaining, 0).toString());
      res.setHeader('X-RateLimit-Reset', Math.max(resetSeconds, 0).toString());

      if (currentCount > config.maxRequests) {
        await redisService.set(blockKey, '1', blockSeconds);
        res.setHeader('Retry-After', blockSeconds.toString());
        res.status(429).json({
          success: false,
          message: config.blockResponseMessage,
          retryAfterSeconds: blockSeconds
        });
        return;
      }

      next();
    } catch (error) {
      logger.warn('Rate limiter encountered an error, allowing request to proceed', 'createAdaptiveRateLimiter', {
        error: error instanceof Error ? error.message : String(error)
      });
      next();
    }
  };
}
