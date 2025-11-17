import {ExecutionContext, Injectable, UnauthorizedException} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {JwtService} from '@nestjs/jwt';
import {AuthGuard} from '@nestjs/passport';
import * as jose from 'jose';
import {LoggerService} from '../../observability/logger.service';
import {JtiAllowlistService} from '../../../platform/redis/jti-allowlist.service';

/**
 * Refresh Token Strategy
 * Cross-cutting auth guard with logout pin validation
 * Supports both plain JWT and JWE-encrypted JWT tokens
 */
@Injectable()
export class RefreshTokenStrategy extends AuthGuard('jwt_refreshToken_guard') {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly logger: LoggerService,
    private readonly jtiAllowlist: JtiAllowlistService
  ) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      throw new UnauthorizedException('No token provided');
    }

    try {
      let jwtToken: string;
      if (this.isJweToken(token)) {
        jwtToken = await this.decryptJweToken(token);
      } else {
        jwtToken = token;
      }

      try {
        await this.validateJwtToken(jwtToken, request);
      } catch (tokenError) {
        this.logger.error({
          message: 'JWT token validation failed',
          details: {
            error: tokenError instanceof Error ? tokenError.message : String(tokenError)
          }
        });
        throw new UnauthorizedException('Invalid or expired refresh token');
      }

      // Validate jti against Redis allowlist
      const sid = request.user.sid;
      const jti = request.user.jti;
      if (!sid || !jti) {
        this.logger.error({message: 'Missing sid/jti in refresh token payload'});
        throw new UnauthorizedException('Invalid token');
      }
      const currentJti = await this.jtiAllowlist.getCurrentJtiForSession(sid);
      if (!currentJti || currentJti !== jti) {
        this.logger.error({message: 'Refresh token reuse detected or session revoked', details: {sid}});
        throw new UnauthorizedException('Invalid token');
      }

      // Removed logoutPin validation; JTI + session allowlist is authoritative

      return true;
    } catch (err) {
      // If it's already an UnauthorizedException, re-throw it
      if (err instanceof UnauthorizedException) {
        throw err;
      }

      // Otherwise, log the error and throw a generic message
      this.logger.error({
        message: 'Refresh token validation failed',
        details: {
          error: err instanceof Error ? err.message : String(err)
        }
      });
      throw new UnauthorizedException('Invalid token');
    }
  }

  private extractTokenFromHeader(request: any): string | null {
    const authHeader = request.headers.authorization;
    if (!authHeader) {
      return null;
    }
    const [, token] = authHeader.split(' ');
    return token;
  }

  private isJweToken(token: string): boolean {
    return token.split('.').length === 5; // JWE tokens have five parts
  }

  private async decryptJweToken(jweToken: string): Promise<string> {
    const secret = this.configService.get<string>('authConfig.token.jweRefreshTokenSecretKey');
    const secretKey = new TextEncoder().encode(secret);
    const {plaintext} = await jose.compactDecrypt(jweToken, secretKey);
    return new TextDecoder().decode(plaintext);
  }

  private async validateJwtToken(token: string, request: any) {
    const secret = this.configService.get<string>('authConfig.token.jwtRefreshTokenSecretKey');
    const decoded = this.jwtService.verify(token, {secret});
    request.user = decoded;
  }
}

