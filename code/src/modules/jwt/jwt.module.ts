import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { JwtStrategy } from './jwt.strategy';
import { PrismaService } from 'src/modules/prisma/prisma.service';

@Module({
    imports: [
        PassportModule,
        JwtModule.registerAsync({
            imports: [ConfigModule],
            useFactory: async (configService: ConfigService) => ({
                secret: configService.get<string>('JWT_SECRET'),
                signOptions: { expiresIn: '365d' },
            }),
            inject: [ConfigService],
        }),
    ],
    providers: [JwtStrategy, PrismaService],
    exports: [JwtModule, PassportModule, JwtStrategy],
})
export class JwtConfigModule {}
