import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

@Injectable()
export class RedisService {
  private redisClient: Redis;
  private readonly logger = new Logger(RedisService.name);

  constructor(private configService: ConfigService) {
    const host = this.configService.get<string>('REDIS_HOST') || 'localhost';
    const port = this.configService.get<number>('REDIS_PORT') || 6379;

    this.logger.log(`Initializing Redis connection to ${host}:${port}`);

    this.redisClient = new Redis({
      host,
      port,
      connectTimeout: 10000, // Increased to 10 seconds
      retryStrategy: times => {
        if (times > 3) {
          this.logger.error('Redis connection failed after 3 retries');
          return null; // Stop retrying
        }
        const delay = Math.min(times * 50, 2000);
        this.logger.warn(`Retrying Redis connection (attempt ${times}) in ${delay}ms`);
        return delay;
      },
      maxRetriesPerRequest: 3,
      enableOfflineQueue: true, // Allow queuing when connection is being established
      lazyConnect: true,
      enableReadyCheck: true // Ensure connection is ready before operations
    });

    this.redisClient.on('error', err => {
      this.logger.error(`Redis connection error: ${err.message}`);
    });

    this.redisClient.on('connect', () => {
      this.logger.log(`Redis connecting to ${host}:${port}`);
    });

    this.redisClient.on('ready', () => {
      this.logger.log('Redis connected and ready');
    });
  }

  private async ensureConnected(): Promise<void> {
    // Check if connection is ready by trying a ping
    try {
      if (this.redisClient.status === 'connect' || this.redisClient.status === 'wait') {
        // Connection is established, return
        return;
      }
    } catch {
      // Status check failed, continue to connection logic
    }

    // If connection is closed or ended, reconnect
    if (this.redisClient.status === 'end' || this.redisClient.status === 'close') {
      await this.redisClient.connect();
    }

    // Wait for connection to be ready if it's connecting or reconnecting
    if (this.redisClient.status === 'reconnecting') {
      return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
          this.redisClient.off('ready', onReady);
          this.redisClient.off('error', onError);
          reject(new Error('Redis connection timeout'));
        }, 10000); // Increased timeout to 10 seconds

        const onReady = () => {
          clearTimeout(timeout);
          this.redisClient.off('ready', onReady);
          this.redisClient.off('error', onError);
          resolve();
        };

        const onError = (err: Error) => {
          clearTimeout(timeout);
          this.redisClient.off('ready', onReady);
          this.redisClient.off('error', onError);
          reject(err);
        };

        this.redisClient.once('ready', onReady);
        this.redisClient.once('error', onError);
      });
    }
  }

  async get(key: string): Promise<string | null> {
    try {
      await this.ensureConnected();
      return await Promise.race([
        this.redisClient.get(key),
        new Promise<null>((_, reject) => setTimeout(() => reject(new Error('Redis get timeout')), 5000))
      ]);
    } catch (error) {
      this.logger.error(`Redis get error for key ${key}: ${error instanceof Error ? error.message : String(error)}`);
      return null;
    }
  }

  async set(key: string, value: string, expireInSec: number): Promise<void> {
    try {
      await this.ensureConnected();

      // Wait for connection to be in a writable state
      if (this.redisClient.status === 'reconnecting' || this.redisClient.status === 'close' || this.redisClient.status === 'end') {
        // Wait up to 2 seconds for connection to become ready
        await new Promise<void>((resolve, reject) => {
          let attempts = 0;
          const maxAttempts = 20; // 20 * 100ms = 2 seconds

          const checkInterval = setInterval(() => {
            attempts++;
            if (this.redisClient.status === 'connect' || this.redisClient.status === 'wait') {
              clearInterval(checkInterval);
              clearTimeout(timeout);
              resolve();
            } else if (attempts >= maxAttempts) {
              clearInterval(checkInterval);
              clearTimeout(timeout);
              reject(new Error(`Redis connection is not ready after ${maxAttempts * 100}ms (status: ${this.redisClient.status})`));
            }
          }, 100);

          const timeout = setTimeout(() => {
            clearInterval(checkInterval);
            reject(new Error('Redis connection timeout while waiting for ready state'));
          }, 2000);
        });
      }

      await Promise.race([
        this.redisClient.set(key, value, 'EX', expireInSec),
        new Promise<never>((_, reject) => setTimeout(() => reject(new Error('Redis set timeout')), 5000))
      ]);
    } catch (error) {
      this.logger.error(`Redis set error for key ${key}: ${error instanceof Error ? error.message : String(error)}`);
      throw error;
    }
  }

  async increment(key: string, expireInSec: number): Promise<number> {
    try {
      await this.ensureConnected();
      const pipeline = this.redisClient.multi();
      pipeline.incr(key);
      pipeline.expire(key, expireInSec, 'NX');
      const results = await pipeline.exec();
      const incrementResult = results?.[0]?.[1];
      return typeof incrementResult === 'number' ? incrementResult : Number(incrementResult ?? 0);
    } catch (error) {
      this.logger.error(`Redis increment error for key ${key}: ${error instanceof Error ? error.message : String(error)}`);
      throw error;
    }
  }

  async ttl(key: string): Promise<number | null> {
    try {
      await this.ensureConnected();
      const ttl = await this.redisClient.ttl(key);
      return ttl >= 0 ? ttl : null;
    } catch (error) {
      this.logger.error(`Redis TTL error for key ${key}: ${error instanceof Error ? error.message : String(error)}`);
      return null;
    }
  }

  async del(key: string): Promise<void> {
    try {
      await this.ensureConnected();
      await Promise.race([this.redisClient.del(key), new Promise<void>(resolve => setTimeout(() => resolve(), 5000))]);
    } catch (error) {
      this.logger.error(`Redis del error for key ${key}: ${error instanceof Error ? error.message : String(error)}`);
      // Don't throw on delete errors - it's not critical
    }
  }

  async keys(pattern: string): Promise<string[]> {
    try {
      await this.ensureConnected();
      return await Promise.race([this.redisClient.keys(pattern), new Promise<string[]>(resolve => setTimeout(() => resolve([]), 5000))]);
    } catch (error) {
      this.logger.error(`Redis keys error for pattern ${pattern}: ${error instanceof Error ? error.message : String(error)}`);
      return [];
    }
  }

  // List operations
  async lrange(key: string, start: number, stop: number): Promise<string[]> {
    try {
      await this.ensureConnected();
      return await this.redisClient.lrange(key, start, stop);
    } catch (error) {
      this.logger.error(`Redis lrange error for key ${key}: ${error instanceof Error ? error.message : String(error)}`);
      return [];
    }
  }

  async lpush(key: string, ...values: string[]): Promise<number> {
    try {
      await this.ensureConnected();
      return await this.redisClient.lpush(key, ...values);
    } catch (error) {
      this.logger.error(`Redis lpush error for key ${key}: ${error instanceof Error ? error.message : String(error)}`);
      throw error;
    }
  }

  async ltrim(key: string, start: number, stop: number): Promise<void> {
    try {
      await this.ensureConnected();
      await this.redisClient.ltrim(key, start, stop);
    } catch (error) {
      this.logger.error(`Redis ltrim error for key ${key}: ${error instanceof Error ? error.message : String(error)}`);
    }
  }

  // Set operations
  async sadd(key: string, ...members: string[]): Promise<number> {
    try {
      await this.ensureConnected();
      return await this.redisClient.sadd(key, ...members);
    } catch (error) {
      this.logger.error(`Redis sadd error for key ${key}: ${error instanceof Error ? error.message : String(error)}`);
      throw error;
    }
  }

  async srem(key: string, ...members: string[]): Promise<number> {
    try {
      await this.ensureConnected();
      return await this.redisClient.srem(key, ...members);
    } catch (error) {
      this.logger.error(`Redis srem error for key ${key}: ${error instanceof Error ? error.message : String(error)}`);
      return 0;
    }
  }

  async scard(key: string): Promise<number> {
    try {
      await this.ensureConnected();
      return await this.redisClient.scard(key);
    } catch (error) {
      this.logger.error(`Redis scard error for key ${key}: ${error instanceof Error ? error.message : String(error)}`);
      return 0;
    }
  }

  async sismember(key: string, member: string): Promise<boolean> {
    try {
      await this.ensureConnected();
      const result = await this.redisClient.sismember(key, member);
      return result === 1;
    } catch (error) {
      this.logger.error(`Redis sismember error for key ${key}: ${error instanceof Error ? error.message : String(error)}`);
      return false;
    }
  }

  // Additional operations
  async incr(key: string): Promise<number> {
    try {
      await this.ensureConnected();
      return await this.redisClient.incr(key);
    } catch (error) {
      this.logger.error(`Redis incr error for key ${key}: ${error instanceof Error ? error.message : String(error)}`);
      throw error;
    }
  }

  async expire(key: string, seconds: number): Promise<boolean> {
    try {
      await this.ensureConnected();
      const result = await this.redisClient.expire(key, seconds);
      return result === 1;
    } catch (error) {
      this.logger.error(`Redis expire error for key ${key}: ${error instanceof Error ? error.message : String(error)}`);
      return false;
    }
  }
}
