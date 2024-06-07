import {Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {PassportStrategy} from '@nestjs/passport';
import {ExtractJwt, Strategy} from 'passport-jwt';
import {PrismaService} from 'src/modules/prisma/prisma.service';
import {unauthorized} from "../auth/utils/string";

@Injectable()
export class JwtRefreshTokenStrategy extends PassportStrategy(Strategy, 'jwt_refreshToken_guard') {
  constructor(
    config: ConfigService,
    private readonly prisma: PrismaService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.get('JWT_REFRESH_TOKEN_SECRET'),
    });
  }

  async validate(payload: any) {
    // Implement your own logic to validate the JWT payload, e.g., check if the user exists in the database.
    // If the payload is valid, return the user object or throw an exception if invalid.
    const existingUser = await this.prisma.user.findUnique({
      where: {
        email: payload.email,
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        verified: true,
        isForgetPassword: true,
      }
    });

    if (!existingUser) {
      return {
        success: false,
        message: unauthorized
      }
    }
    return existingUser;
  }
}



