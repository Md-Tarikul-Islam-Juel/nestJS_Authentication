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
  jweAccessTokenSecretKey: string;
  jwtAccessTokenSecretKey: string;
  jweJwtAccessTokenExpireTime: string;
  jweRefreshTokenSecretKey: string;
  jwtRefreshTokenSecretKey: string;
  jweJwtRefreshTokenExpireTime: string;
}
