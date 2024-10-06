import {Injectable, ExecutionContext, UnauthorizedException} from '@nestjs/common';
import {AuthGuard} from '@nestjs/passport';
import {JwtService} from '@nestjs/jwt';
import {ConfigService} from '@nestjs/config';
import * as jose from 'jose';

@Injectable()
export class JweJwtRefreshTokenStrategy extends AuthGuard('jwt_refreshToken_guard') {
  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
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
      await this.validateJwtToken(jwtToken, request);

      return true;
    } catch (err) {
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
    const secret = this.configService.get<string>('tokenConfig.token.jweRefreshTokenSecretKey');
    const {plaintext} = await jose.compactDecrypt(jweToken, Buffer.from(secret, 'utf-8'));
    return new TextDecoder().decode(plaintext);
  }

  private async validateJwtToken(token: string, request: any) {
    const secret = this.configService.get<string>('tokenConfig.token.jwtRefreshTokenSecretKey');
    const decoded = this.jwtService.verify(token, {secret});
    request.user = decoded;
  }
}
