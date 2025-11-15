/**
 * JWT Service Port
 * Domain layer interface for JWT token generation
 * Following Clean Architecture: application layer depends on domain abstractions
 */

/**
 * Token Payload - User data encoded in JWT tokens
 * Domain concept defining what user information is included in tokens
 */
export interface TokenPayload {
  id: number;
  email: string;
  logoutPin?: string;
  [key: string]: any;
}

/**
 * Token Configuration - Settings for JWT token generation
 * Domain concept defining how tokens are generated (JWE, expiration, secrets)
 */
export interface TokenConfig {
  useJwe: boolean;
  jweAccessTokenSecretKey: string;
  jwtAccessTokenSecretKey: string;
  jweJwtAccessTokenExpireTime: string;
  jweRefreshTokenSecretKey: string;
  jwtRefreshTokenSecretKey: string;
  jweJwtRefreshTokenExpireTime: string;
}

/**
 * Tokens - Access and refresh token pair
 * Domain concept representing the token response structure
 */
export interface Tokens {
  accessToken: string;
  refreshToken: string;
}

/**
 * JWT Service Port interface
 * Defines the contract for token generation services
 */
export interface JwtServicePort {
  /**
   * Generate both access and refresh tokens
   */
  generateTokens(user: TokenPayload, config: TokenConfig): Promise<Tokens>;
}
