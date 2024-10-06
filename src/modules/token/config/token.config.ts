import {registerAs} from '@nestjs/config';

export default registerAs('tokenConfig', () => ({
  token: {
    jweAccessTokenSecretKey: process.env.JWE_ACCESS_TOKEN_SECRET ?? '1234567890abcdef1234567890abcdef',
    jwtAccessTokenSecretKey: process.env.JWT_ACCESS_TOKEN_SECRET ?? 'abcdefghijklmnopqrstuvwxyza123456',
    jweJwtAccessTokenExpireTime: process.env.JWE_JWT_ACCESS_TOKEN_EXPIRATION ?? '86400s', // default to 1 day
    jweRefreshTokenSecretKey: process.env.JWE_REFRESH_TOKEN_SECRET ?? 'abcdef1234567890abcdef1234567890',
    jwtRefreshTokenSecretKey: process.env.JWT_REFRESH_TOKEN_SECRET ?? 'abcdefghijklmnopqrstuvwxz1234567',
    jweJwtRefreshTokenExpireTime: process.env.JWE_JWT_REFRESH_TOKEN_EXPIRATION ?? '30d' // default to 30 days
  }
}));
