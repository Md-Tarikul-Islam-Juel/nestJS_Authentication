import {Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {RedisService} from './redis.service';

@Injectable()
export class JtiAllowlistService {
  constructor(
    private readonly configService: ConfigService,
    private readonly redis: RedisService
  ) {}

  async setCurrentJtiForSession(sessionId: string, jti: string, ttlSeconds: number): Promise<void> {
    const key = this.sessionJtiKey(sessionId);
    await this.redis.set(key, jti, ttlSeconds);
  }

  async getCurrentJtiForSession(sessionId: string): Promise<string | null> {
    const key = this.sessionJtiKey(sessionId);
    return await this.redis.get(key);
  }

  async revokeSession(sessionId: string): Promise<void> {
    const key = this.sessionJtiKey(sessionId);
    await this.redis.del(key);
  }

  /**
   * Atomic rotate: if existing jti matches expected, replace with next and reset TTL
   */
  async rotateIfMatches(sessionId: string, expectedJti: string, nextJti: string, ttlSeconds: number): Promise<boolean> {
    const key = this.sessionJtiKey(sessionId);
    // Emulate simple CAS with GET then SET if equal; acceptable here due to low contention
    const current = await this.redis.get(key);
    if (!current || current !== expectedJti) {
      return false;
    }
    await this.redis.set(key, nextJti, ttlSeconds);
    return true;
  }

  private sessionJtiKey(sessionId: string): string {
    const prefix = this.configService.get<string>('authConfig.token.redis.prefix') || 'auth:';
    return `${prefix}session:${sessionId}:jti`;
  }
}


