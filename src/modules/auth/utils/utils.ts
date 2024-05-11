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

//at least one number, one uppercase, one lowe case, one special character
export function randomPasswordGenerator(length: number): string {
    const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?";
    let code = "";

    // Ensure at least one number is included
    const randomNumber = Math.floor(Math.random() * 10);
    code += randomNumber.toString();

    // Generate the remaining characters
    for (let i = 1; i < length; i++) {
        const randomIndex = Math.floor(Math.random() * charset.length);
        code += charset[randomIndex];
    }

    return code;
}