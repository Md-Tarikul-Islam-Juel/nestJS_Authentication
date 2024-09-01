import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { PrismaService } from 'src/modules/prisma/prisma.service';
import { JweJwtAccessTokenStrategy } from './jwe-jwt-access-token.strategy';
import { JweJwtRefreshTokenStrategy } from './jwe-jwt-refresh-token.strategy';


@Module({
  imports: [
    PassportModule,
    JwtModule,
  ],
  providers: [JweJwtAccessTokenStrategy, JweJwtRefreshTokenStrategy, PrismaService],
  exports: [JwtModule, PassportModule, JweJwtAccessTokenStrategy, JweJwtRefreshTokenStrategy],
})
export class JwtConfigModule {
}
