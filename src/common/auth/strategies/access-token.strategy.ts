import {ExecutionContext, Injectable, UnauthorizedException} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {GqlExecutionContext} from '@nestjs/graphql';
import {JwtService} from '@nestjs/jwt';
import {AuthGuard} from '@nestjs/passport';
import * as jose from 'jose';

/**
 * Access Token Strategy
 * Cross-cutting auth guard for HTTP and GraphQL
 * Supports both plain JWT and JWE-encrypted JWT tokens
 */
@Injectable()
export class AccessTokenStrategy extends AuthGuard('jwt_accessToken_guard') {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService
  ) {
    super();
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = this.getRequest(context);
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
      await this.validateJwtToken(jwtToken, request);

      return true;
    } catch (err) {
      throw new UnauthorizedException('Invalid token');
    }
  }

  public getRequest(context: ExecutionContext): any {
    const contextType = context.getType<'http' | 'graphql'>();
    if (contextType === 'http') {
      return context.switchToHttp().getRequest();
    } else if (contextType === 'graphql') {
      const ctx = GqlExecutionContext.create(context);
      return ctx.getContext().req;
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
    const secret = this.configService.get<string>('authConfig.token.jweAccessTokenSecretKey');
    const secretKey = new TextEncoder().encode(secret);
    const {plaintext} = await jose.compactDecrypt(jweToken, secretKey);
    return new TextDecoder().decode(plaintext);
  }

  private async validateJwtToken(token: string, request: any) {
    const secret = this.configService.get<string>('authConfig.token.jwtAccessTokenSecretKey');
    const decoded = this.jwtService.verify(token, {secret});
    request.user = decoded;
  }
}

