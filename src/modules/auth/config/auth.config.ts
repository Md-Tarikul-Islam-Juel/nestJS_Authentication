import { registerAs } from '@nestjs/config';

export default registerAs('authConfig', () => ({
  bcryptSaltRounds: parseInt(process.env.BCRYPT_SALT_ROUNDS, 10),
  otpExpireTime: parseInt(process.env.OTP_EXPIRE_TIME, 10), // OTP expiration time in minutes
  jweAccessTokenSecretKey: process.env.JWE_ACCESS_TOKEN_SECRET,
  jwtAccessTokenSecretKey: process.env.JWT_ACCESS_TOKEN_SECRET,
  jweJwtAccessTokenExpireTime: process.env.JWE_JWT_ACCESS_TOKEN_EXPIRATION,
  jweRefreshTokenSecretKey: process.env.JWE_REFRESH_TOKEN_SECRET,
  jwtRefreshTokenSecretKey: process.env.JWT_REFRESH_TOKEN_SECRET,
  jweJwtRefreshTokenExpireTime: process.env.JWE_JWT_REFRESH_TOKEN_EXPIRATION,
  email: {
    host: process.env.OTP_SENDER_MAIL_HOST,
    port: parseInt(process.env.OTP_SENDER_MAIL_PORT, 10),
    email: process.env.OTP_SENDER_MAIL,
    pass: process.env.OTP_SENDER_MAIL_PASSWORD,
  },
}));
