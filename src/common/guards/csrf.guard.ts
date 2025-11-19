import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import * as crypto from 'crypto';
import { RedisService } from '../../platform/redis/redis.service';

/**
 * CSRF Guard - Protects against Cross-Site Request Forgery attacks
 * 
 * Implementation:
 * 1. Double Submit Cookie Pattern
 * 2. Token stored in Redis with session binding
 * 3. Validates token from header matches session token
 * 
 * Usage:
 * @UseGuards(CsrfGuard)
 * @Post('change-password')
 * async changePassword() { ... }
 * 
 * To skip CSRF for specific endpoints:
 * @SkipCsrf()
 * @Post('webhook')
 * async handleWebhook() { ... }
 */

export const SKIP_CSRF_KEY = 'skip_csrf';
export const SkipCsrf = () => Reflector.prototype.constructor(SKIP_CSRF_KEY, true);

@Injectable()
export class CsrfGuard implements CanActivate {
  private readonly TOKEN_HEADER = 'x-csrf-token';
  private readonly TOKEN_EXPIRY = 3600; // 1 hour

  constructor(
    private readonly reflector: Reflector,
    private readonly redis: RedisService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    // Check if CSRF should be skipped for this endpoint
    const skipCsrf = this.reflector.get<boolean>(
      SKIP_CSRF_KEY,
      context.getHandler(),
    );

    if (skipCsrf) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request>();
    const method = request.method.toUpperCase();

    // Only check CSRF for state-changing operations
    if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
      return true;
    }

    // Extract user ID from JWT token (set by AccessTokenStrategy)
    const userId = (request as any).user?.id;
    if (!userId) {
      throw new UnauthorizedException('User not authenticated');
    }

    // Get CSRF token from header
    const csrfToken = request.headers[this.TOKEN_HEADER] as string;
    if (!csrfToken) {
      throw new ForbiddenException('CSRF token missing');
    }

    // Validate token
    const isValid = await this.validateToken(userId, csrfToken);
    if (!isValid) {
      throw new ForbiddenException('Invalid or expired CSRF token');
    }

    return true;
  }

  /**
   * Generate a new CSRF token for a user
   */
  async generateToken(userId: number): Promise<string> {
    const token = crypto.randomBytes(32).toString('hex');
    const key = this.getRedisKey(userId);

    // Store token in Redis with expiry
    await this.redis.set(key, token, this.TOKEN_EXPIRY);

    return token;
  }

  /**
   * Validate CSRF token
   */
  private async validateToken(userId: number, token: string): Promise<boolean> {
    const key = this.getRedisKey(userId);
    const storedToken = await this.redis.get(key);

    if (!storedToken) {
      return false;
    }

    // Constant-time comparison to prevent timing attacks
    return this.secureCompare(token, storedToken);
  }

  /**
   * Revoke CSRF token (e.g., on logout)
   */
  async revokeToken(userId: number): Promise<void> {
    const key = this.getRedisKey(userId);
    await this.redis.del(key);
  }

  /**
   * Get Redis key for user's CSRF token
   */
  private getRedisKey(userId: number): string {
    return `csrf:token:${userId}`;
  }

  /**
   * Constant-time string comparison to prevent timing attacks
   */
  private secureCompare(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return result === 0;
  }
}
