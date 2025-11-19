import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { RedisService } from './redis.service';

@Injectable()
export class UserSessionIndexService {
  constructor(
    private readonly configService: ConfigService,
    private readonly redis: RedisService
  ) { }

  async addSession(userId: number, sessionId: string, ttlSeconds: number): Promise<void> {
    const key = this.userSessionsKey(userId);
    // Store as a simple append list in Redis keys pattern to avoid requiring Redis sets
    // We'll maintain existence by setting a parallel TTL key (optional)
    const memberKey = this.userSessionMemberKey(userId, sessionId);
    await this.redis.set(memberKey, '1', ttlSeconds);
  }

  async listSessions(userId: number): Promise<string[]> {
    const pattern = this.userSessionMemberKey(userId, '*');
    const keys = await this.redis.keys(pattern);
    return keys.map(k => k.substring(k.lastIndexOf(':') + 1));
  }

  async getAllSessions(userId: number): Promise<string[]> {
    return this.listSessions(userId);
  }

  async removeSession(userId: number, sessionId: string): Promise<void> {
    const memberKey = this.userSessionMemberKey(userId, sessionId);
    await this.redis.del(memberKey);
  }

  async revokeAll(userId: number, allowlistKeyForSid: (sid: string) => string): Promise<number> {
    const sids = await this.listSessions(userId);
    let revoked = 0;
    for (const sid of sids) {
      // Delete allowlisted jti per sid
      await this.redis.del(allowlistKeyForSid(sid));
      // Remove session index member
      await this.removeSession(userId, sid);
      revoked++;
    }
    return revoked;
  }

  private userSessionsKey(userId: number): string {
    const prefix = this.configService.get<string>('authConfig.token.redis.prefix') || 'auth:';
    return `${prefix}user:${userId}:sessions`;
  }

  private userSessionMemberKey(userId: number, sessionId: string | '*'): string {
    const prefix = this.configService.get<string>('authConfig.token.redis.prefix') || 'auth:';
    return `${prefix}user:${userId}:session:${sessionId}`;
  }
}


