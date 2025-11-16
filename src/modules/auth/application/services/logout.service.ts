import {Inject, Injectable} from '@nestjs/common';
import {JtiAllowlistService} from '../../../../platform/redis/jti-allowlist.service';
import {UserSessionIndexService} from '../../../../platform/redis/user-session-index.service';
import {UserNotFoundError} from '../../domain/errors/user-not-found.error';
import type {UserRepositoryPort} from '../../domain/repositories/user.repository.port';
import {USER_REPOSITORY_PORT} from '../di-tokens';

/**
 * Logout Service
 * Application layer service for logout operations
 * Following Clean Architecture: all database queries go through repository
 */
@Injectable()
export class LogoutService {
  constructor(
    @Inject(USER_REPOSITORY_PORT)
    private readonly userRepository: UserRepositoryPort,
    private readonly jtiAllowlist: JtiAllowlistService,
    private readonly userSessionIndex: UserSessionIndexService
  ) {}

  async logoutFromAllDevices(userId: number): Promise<string> {
    // Following Clean Architecture: all database queries go through repository
    // Verify user exists and is not soft-deleted
    const user = await this.userRepository.findById(userId);

    if (!user) {
      throw new UserNotFoundError();
    }

    // Revoke all sessions for this user by clearing all allowlisted JTIs for their session IDs
    const revoked = await this.userSessionIndex.revokeAll(userId, (sid: string) => {
      // build allowlist key for sid
      const prefix = (this as any).jtiAllowlist['configService']?.get?.('authConfig.token.redis.prefix') || 'auth:';
      return `${prefix}session:${sid}:jti`;
    });

    return revoked > 0 ? 'Logged out from all devices.' : 'No active sessions found.';
  }
}
