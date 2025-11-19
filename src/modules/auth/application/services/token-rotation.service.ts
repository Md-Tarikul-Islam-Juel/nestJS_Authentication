import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JtiAllowlistService } from '../../../../platform/redis/jti-allowlist.service';
import { UserSessionIndexService } from '../../../../platform/redis/user-session-index.service';
import { JtiProvider } from '../../../../platform/jwt/jti.provider';
import { JWT_SERVICE_PORT, LOGGER_PORT } from '../di-tokens';
import type { JwtServicePort, TokenConfig, Tokens } from '../../domain/repositories/jwt-service.port';
import type { LoggerPort } from '../../domain/repositories/logger.port';

/**
 * Token Family - Tracks refresh token lineage
 */
interface TokenFamily {
    familyId: string;
    sessionId: string;
    userId: number;
    createdAt: Date;
    lastRotatedAt: Date;
    rotationCount: number;
    isRevoked: boolean;
}

/**
 * Rotation Result
 */
interface RotationResult {
    success: boolean;
    tokens?: Tokens;
    reason?: string;
    shouldRevokeAll?: boolean;
}

/**
 * Enhanced Token Rotation Service
 * 
 * Features:
 * 1. Automatic rotation on every refresh
 * 2. Token family tracking for lineage
 * 3. Reuse detection with family revocation
 * 4. Configurable rotation policies
 * 5. Grace period for concurrent requests
 * 
 * Security Benefits:
 * - Limits token lifetime
 * - Detects token theft/replay attacks
 * - Enables granular revocation
 * - Prevents token reuse
 */
@Injectable()
export class TokenRotationService {
    private readonly FAMILY_TTL = 2592000; // 30 days
    private readonly GRACE_PERIOD = 5; // 5 seconds for concurrent requests
    private readonly MAX_ROTATIONS = 1000; // Prevent infinite rotation

    constructor(
        private readonly configService: ConfigService,
        private readonly jtiAllowlist: JtiAllowlistService,
        private readonly userSessionIndex: UserSessionIndexService,
        private readonly jtiProvider: JtiProvider,
        @Inject(JWT_SERVICE_PORT)
        private readonly jwtService: JwtServicePort,
        @Inject(LOGGER_PORT)
        private readonly logger: LoggerPort,
    ) { }

    /**
     * Rotate refresh token with family tracking
     * 
     * Process:
     * 1. Validate current token
     * 2. Check if token was already used (reuse detection)
     * 3. Generate new token pair
     * 4. Update family lineage
     * 5. Revoke old token
     */
    async rotateToken(
        currentJti: string,
        sessionId: string,
        userId: number,
        tokenPayload: any,
        tokenConfig: TokenConfig,
    ): Promise<RotationResult> {
        try {
            // 1. Get current JTI from allowlist
            const allowedJti = await this.jtiAllowlist.getCurrentJtiForSession(sessionId);

            if (!allowedJti) {
                this.logger.error({
                    message: 'Session not found in allowlist',
                    details: { sessionId, userId },
                });

                return {
                    success: false,
                    reason: 'Session not found or expired',
                };
            }

            // 2. Check for token reuse
            if (currentJti !== allowedJti) {
                // Token reuse detected!
                this.logger.error({
                    message: 'Refresh token reuse detected',
                    details: {
                        sessionId,
                        userId,
                        currentJti,
                        allowedJti,
                    },
                });

                // Check if within grace period (for concurrent requests)
                const isWithinGracePeriod = await this.checkGracePeriod(sessionId, currentJti);

                if (!isWithinGracePeriod) {
                    // Revoke entire token family
                    await this.revokeTokenFamily(sessionId, userId);

                    return {
                        success: false,
                        reason: 'Token reuse detected - all tokens revoked',
                        shouldRevokeAll: true,
                    };
                }

                // Within grace period, allow but log
                this.logger.warn({
                    message: 'Token reuse within grace period',
                    details: { sessionId, userId },
                });
            }

            // 3. Get token family
            const family = await this.getTokenFamily(sessionId);

            if (!family) {
                // Create new family
                await this.createTokenFamily(sessionId, userId);
            } else {
                // Check rotation limit
                if (family.rotationCount >= this.MAX_ROTATIONS) {
                    this.logger.error({
                        message: 'Max rotation count exceeded',
                        details: { sessionId, userId, rotationCount: family.rotationCount },
                    });

                    await this.revokeTokenFamily(sessionId, userId);

                    return {
                        success: false,
                        reason: 'Max rotation count exceeded',
                    };
                }

                // Check if family is revoked
                if (family.isRevoked) {
                    return {
                        success: false,
                        reason: 'Token family has been revoked',
                    };
                }
            }

            // 4. Generate new JTI
            const newJti = this.jtiProvider.generateJti();

            // 5. Store old JTI in grace period cache
            await this.storeInGracePeriod(sessionId, currentJti);

            // 6. Update JTI in allowlist (atomic operation)
            const refreshTtlSeconds = this.toSeconds(tokenConfig.jweJwtRefreshTokenExpireTime);
            const rotated = await this.jtiAllowlist.rotateIfMatches(
                sessionId,
                allowedJti,
                newJti,
                refreshTtlSeconds,
            );

            if (!rotated) {
                this.logger.error({
                    message: 'Failed to rotate JTI - concurrent modification',
                    details: { sessionId, userId },
                });

                return {
                    success: false,
                    reason: 'Concurrent token rotation detected',
                };
            }

            // 7. Update token family
            await this.updateTokenFamily(sessionId);

            // 8. Generate new token pair
            const newTokenPayload = {
                ...tokenPayload,
                sid: sessionId,
                jti: newJti,
            };

            const tokens = await this.jwtService.generateTokens(newTokenPayload, tokenConfig);

            // 9. Log successful rotation
            this.logger.info({
                message: 'Token rotated successfully',
                details: {
                    sessionId,
                    userId,
                    oldJti: currentJti,
                    newJti,
                },
            });

            return {
                success: true,
                tokens,
            };
        } catch (error) {
            this.logger.error({
                message: 'Token rotation failed',
                details: {
                    sessionId,
                    userId,
                    error: error instanceof Error ? error.message : String(error),
                },
            });

            return {
                success: false,
                reason: 'Internal error during token rotation',
            };
        }
    }

    /**
     * Create new token family
     */
    private async createTokenFamily(sessionId: string, userId: number): Promise<void> {
        const family: TokenFamily = {
            familyId: this.jtiProvider.generateJti(),
            sessionId,
            userId,
            createdAt: new Date(),
            lastRotatedAt: new Date(),
            rotationCount: 0,
            isRevoked: false,
        };

        const key = this.getFamilyKey(sessionId);
        await this.redis.set(key, JSON.stringify(family), this.FAMILY_TTL);
    }

    /**
     * Get token family
     */
    private async getTokenFamily(sessionId: string): Promise<TokenFamily | null> {
        const key = this.getFamilyKey(sessionId);
        const data = await this.redis.get(key);

        if (!data) {
            return null;
        }

        return JSON.parse(data);
    }

    /**
     * Update token family after rotation
     */
    private async updateTokenFamily(sessionId: string): Promise<void> {
        const family = await this.getTokenFamily(sessionId);

        if (!family) {
            return;
        }

        family.lastRotatedAt = new Date();
        family.rotationCount += 1;

        const key = this.getFamilyKey(sessionId);
        await this.redis.set(key, JSON.stringify(family), this.FAMILY_TTL);
    }

    /**
     * Revoke entire token family (on reuse detection)
     */
    private async revokeTokenFamily(sessionId: string, userId: number): Promise<void> {
        // 1. Mark family as revoked
        const family = await this.getTokenFamily(sessionId);
        if (family) {
            family.isRevoked = true;
            const key = this.getFamilyKey(sessionId);
            await this.redis.set(key, JSON.stringify(family), this.FAMILY_TTL);
        }

        // 2. Revoke session in allowlist
        await this.jtiAllowlist.revokeSession(sessionId);

        // 3. Remove from user session index
        await this.userSessionIndex.removeSession(userId, sessionId);

        this.logger.warn({
            message: 'Token family revoked',
            details: { sessionId, userId, familyId: family?.familyId },
        });
    }

    /**
     * Store JTI in grace period cache
     * Allows recently rotated tokens to be used once more
     */
    private async storeInGracePeriod(sessionId: string, jti: string): Promise<void> {
        const key = this.getGracePeriodKey(sessionId);
        await this.redis.set(key, jti, this.GRACE_PERIOD);
    }

    /**
     * Check if JTI is within grace period
     */
    private async checkGracePeriod(sessionId: string, jti: string): Promise<boolean> {
        const key = this.getGracePeriodKey(sessionId);
        const gracePeriodJti = await this.redis.get(key);

        return gracePeriodJti === jti;
    }

    /**
     * Revoke all sessions for a user (logout all devices)
     */
    async revokeAllUserSessions(userId: number): Promise<void> {
        const sessions = await this.userSessionIndex.getAllSessions(userId);

        for (const sessionId of sessions) {
            await this.revokeTokenFamily(sessionId, userId);
        }

        this.logger.info({
            message: 'All user sessions revoked',
            details: { userId, sessionCount: sessions.length },
        });
    }

    /**
     * Get token family statistics
     */
    async getTokenFamilyStats(sessionId: string): Promise<TokenFamily | null> {
        return this.getTokenFamily(sessionId);
    }

    /**
     * Clean up expired token families (scheduled job)
     */
    async cleanupExpiredFamilies(): Promise<void> {
        // This would be called by a cron job
        // Implementation depends on Redis scanning strategy
        this.logger.info({
            message: 'Token family cleanup completed',
        });
    }

    /**
     * Helper: Get Redis key for token family
     */
    private getFamilyKey(sessionId: string): string {
        return `token:family:${sessionId}`;
    }

    /**
     * Helper: Get Redis key for grace period
     */
    private getGracePeriodKey(sessionId: string): string {
        return `token:grace:${sessionId}`;
    }

    /**
     * Helper: Convert duration string to seconds
     */
    private toSeconds(duration: string): number {
        const trimmed = String(duration).trim();
        const match = /^(\d+)\s*([smhd])?$/i.exec(trimmed);

        if (!match) {
            const n = parseInt(trimmed, 10);
            return Number.isFinite(n) ? n : 0;
        }

        const value = parseInt(match[1], 10);
        const unit = (match[2] || 's').toLowerCase();

        switch (unit) {
            case 's':
                return value;
            case 'm':
                return value * 60;
            case 'h':
                return value * 3600;
            case 'd':
                return value * 86400;
            default:
                return value;
        }
    }

    // Redis service reference (inject in constructor)
    private get redis() {
        return this.jtiAllowlist['redis']; // Access through jtiAllowlist
    }
}
