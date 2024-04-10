import {JwtService} from '@nestjs/jwt';

export function generateJwtToken(jwtService: JwtService, existingUser: any): string {
    const {password, updatedAt, createdAt, ...restUser} = existingUser;
    const payload = {...restUser};
    return jwtService.sign(payload);
}
