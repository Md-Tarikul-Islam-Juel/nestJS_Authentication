import {JwtService} from '@nestjs/jwt';

export function generateJwtAccessToken(jwtService: JwtService, existingUser: any): string {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const {password, updatedAt, createdAt, ...restUser} = existingUser;
    const payload = {...restUser};
    return jwtService.sign(payload,{ expiresIn: '60s', secret: process.env.JWT_ACCESS_TOKEN_SECRET });
}

export function generateJwtRefreshToken(jwtService: JwtService, existingUser: any): string {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const {password, updatedAt, createdAt, ...restUser} = existingUser;
    const payload = {...restUser};
    return jwtService.sign(payload, { expiresIn: '30d', secret: process.env.JWT_REFRESH_TOKEN_SECRET });
}