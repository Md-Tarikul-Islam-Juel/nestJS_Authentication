import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { PrismaService } from 'src/modules/prisma/prisma.service';
import { JwtAccessTokenStrategy } from './jwt-access-token.strategy';
import { JwtRefreshTokenStrategy } from './jwt-refresh-token.strategy';

@Module({
    imports: [
        PassportModule,
        JwtModule
    ],
    providers: [JwtAccessTokenStrategy,JwtRefreshTokenStrategy, PrismaService],
    exports: [JwtModule, PassportModule, JwtAccessTokenStrategy, JwtRefreshTokenStrategy],
})
export class JwtConfigModule {}
