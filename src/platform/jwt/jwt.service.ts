import {Injectable} from '@nestjs/common';
import {JwtService} from '@nestjs/jwt';
import * as jose from 'jose';
import {CompactEncrypt} from 'jose';
// Import types from domain layer (domain defines the contract)
import type {TokenConfig, TokenPayload, Tokens} from '../../modules/auth/domain/repositories/jwt-service.port';

// Re-export types for backward compatibility (platform can export domain types)
export type {TokenConfig, TokenPayload, Tokens};

/**
 * JWT Service - Core token generation and validation
 * Part of platform infrastructure layer
 */
@Injectable()
export class PlatformJwtService {
  constructor(private readonly jwtService: JwtService) {}

  /**
   * Generate both access and refresh tokens
   */
  async generateTokens(user: TokenPayload, config: TokenConfig): Promise<Tokens> {
    const accessToken = await this.generateAccessToken(user, config);
    const refreshToken = await this.generateRefreshToken(user, config);
    return {accessToken, refreshToken};
  }

  /**
   * Generate access token (JWE-encrypted if enabled, otherwise plain JWT)
   */
  async generateAccessToken(user: TokenPayload, config: TokenConfig): Promise<string> {
    // Sign JWT
    const jwtToken = this.jwtService.sign(user, {
      expiresIn: config.jweJwtAccessTokenExpireTime,
      secret: config.jwtAccessTokenSecretKey
    });

    // Conditionally encrypt with JWE
    return config.useJwe ? this.encryptToken(jwtToken, config.jweAccessTokenSecretKey) : jwtToken;
  }

  /**
   * Generate refresh token (JWE-encrypted if enabled, otherwise plain JWT)
   */
  async generateRefreshToken(user: TokenPayload, config: TokenConfig): Promise<string> {
    // Sign JWT
    const jwtToken = this.jwtService.sign(user, {
      expiresIn: config.jweJwtRefreshTokenExpireTime,
      secret: config.jwtRefreshTokenSecretKey
    });

    // Conditionally encrypt with JWE
    return config.useJwe ? this.encryptToken(jwtToken, config.jweRefreshTokenSecretKey) : jwtToken;
  }

  /**
   * Verify and decrypt JWT token
   */
  async verifyAndDecrypt(token: string, jwtSecret: string, jweSecret: string): Promise<any> {
    // Decrypt JWE if needed
    const decryptedToken = this.isJweToken(token) ? await this.decryptJweToken(token, jweSecret) : token;

    // Verify JWT
    return this.jwtService.verify(decryptedToken, {secret: jwtSecret});
  }

  /**
   * Check if token is JWE-encrypted
   */
  private isJweToken(token: string): boolean {
    return token.split('.').length === 5; // JWE tokens have 5 parts
  }

  /**
   * Encrypt token with JWE
   */
  private async encryptToken(token: string, secretKey: string): Promise<string> {
    const jweSecretKey = new TextEncoder().encode(secretKey);
    return await new CompactEncrypt(new TextEncoder().encode(token)).setProtectedHeader({alg: 'dir', enc: 'A256GCM'}).encrypt(jweSecretKey);
  }

  /**
   * Decrypt JWE token
   */
  private async decryptJweToken(jweToken: string, secretKey: string): Promise<string> {
    const jweSecretKey = new TextEncoder().encode(secretKey);
    const {plaintext} = await jose.compactDecrypt(jweToken, jweSecretKey);
    return new TextDecoder().decode(plaintext);
  }
}
