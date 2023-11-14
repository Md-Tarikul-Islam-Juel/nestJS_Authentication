import { Injectable, UnauthorizedException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { PrismaService } from 'src/prisma/prisma.service';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'my_jwt_guard') {
  constructor(
    config: ConfigService,
    private readonly prisma: PrismaService,
  ) {
    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: config.get('JWT_SECRET'),
    });
    console.log('');
  }
  async validate(payload: any) {
    // Implement your own logic to validate the JWT payload, e.g., check if the user exists in the database.
    // If the payload is valid, return the user object or throw an exception if invalid.
    const existingUser = await this.prisma.user.findUnique({
      where: {
        email: payload.email,
      },
    });

    if (!existingUser) {
      throw new UnauthorizedException('User not found');
    }

    // console.log(existingUser);
    // return existingUser;
    // Create a copy of the user object without the hashed password
    const {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      password,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      createdAt,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      updatedAT,

      ...restUser
    } = existingUser;
    const userWithoutSomeInfo = { ...restUser };

    // console.log(userWithoutSomeData);
    // Return a success message and the user (without password)
    return userWithoutSomeInfo;
  }
}
