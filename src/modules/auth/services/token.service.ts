import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { CompactEncrypt } from 'jose';
import { Tokens } from '../dtos/auth.base.dto';
import { TokenPayloadInterface } from '../interfaces/auth.interface';

interface TokenConfig {
  jweAccessTokenSecretKey: string;
  jwtAccessTokenSecretKey: string;
  jweJwtAccessTokenExpireTime: string;
  jweRefreshTokenSecretKey: string;
  jwtRefreshTokenSecretKey: string;
  jweJwtRefreshTokenExpireTime: string;
}

@Injectable()
export class TokenService {
  constructor(
    private jwtAccessToken: JwtService,
    private jwtRefreshToken: JwtService,
  ) {
  }

  public async generateTokens(user: TokenPayloadInterface, tokenConfig: TokenConfig): Promise<Tokens> {
    const accessToken: string = await this.generateJwtAccessToken(this.jwtAccessToken, user, tokenConfig);
    const refreshToken: string = await this.generateJwtRefreshToken(this.jwtRefreshToken, user, tokenConfig);

    return { accessToken, refreshToken };
  }

  public async generateJwtAccessToken(jwtService: JwtService, existingUser: TokenPayloadInterface, tokenConfig: TokenConfig): Promise<string> {
    const jwtToken: string = jwtService.sign(existingUser, {
      expiresIn: tokenConfig.jweJwtAccessTokenExpireTime,
      secret: tokenConfig.jwtAccessTokenSecretKey,
    });

    return this.encryptToken(jwtToken, tokenConfig.jweAccessTokenSecretKey);
  }

  public async generateJwtRefreshToken(jwtService: JwtService, existingUser: TokenPayloadInterface, tokenConfig: TokenConfig): Promise<string> {
    const jwtToken: string = jwtService.sign(existingUser, {
      expiresIn: tokenConfig.jweJwtRefreshTokenExpireTime,
      secret: tokenConfig.jwtRefreshTokenSecretKey,
    });

    return this.encryptToken(jwtToken, tokenConfig.jweRefreshTokenSecretKey);
  }

  private async encryptToken(token: string, secretKey: string): Promise<string> {
    const jweSecretKey = new TextEncoder().encode(secretKey);
    return await new CompactEncrypt(new TextEncoder().encode(token))
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .encrypt(jweSecretKey);
  }
}
