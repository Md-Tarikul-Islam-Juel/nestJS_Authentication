export interface ExistingUserInterface {
  id: number;
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  verified: boolean;
  isForgetPassword: boolean;
  mfaEnabled: boolean;
  failedOtpAttempts: number;
  accountLockedUntil?: Date;
}

export interface CreatedUserInterface {
  id: number;
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  verified: boolean;
  isForgetPassword: boolean;
}

export interface TokenPayloadInterface {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
  verified: boolean;
  isForgetPassword: boolean;
  TokenPayloadInterface: string;
}

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
 * OAuth User Interface
 * Represents user data from OAuth providers (Google, Facebook)
 */
export interface OAuthUser {
  email: string;
  firstName?: string;
  lastName?: string;
  loginSource?: string;
  authorizerId?: string;
}

/**
 * Request with user payload
 * Used for authenticated requests that include user information
 */
export interface AuthenticatedRequest {
  user: {
    id: number;
    email: string;
    [key: string]: unknown;
  };
}

/**
 * User with logout pin
 * Extends ExistingUserInterface to include logoutPin for token generation
 */
export interface UserWithLogoutPin extends ExistingUserInterface {
  logoutPin?: string;
}
