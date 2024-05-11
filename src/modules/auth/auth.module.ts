import {Module} from '@nestjs/common';
import {PrismaModule} from 'src/modules/prisma/prisma.module';
import {AuthController} from './controllers/auth.controller';
import {LoggerModule} from "../logger/logger.module";
import {AuthService} from "./services/auth.service";
import {JwtConfigModule} from "../jwt/jwt.module";
import { JwtAccessTokenStrategy } from '../jwt/jwt-access-token.strategy';
import { JwtRefreshTokenStrategy } from '../jwt/jwt-refresh-token.strategy';
import { GoogleStrategy } from './strategy/google.strategy';


@Module({
    imports: [
        PrismaModule,
        LoggerModule,
        JwtConfigModule
    ],
    controllers: [AuthController],
    providers: [AuthService, JwtAccessTokenStrategy, JwtRefreshTokenStrategy, GoogleStrategy],
    exports: [AuthService],
})
export class AuthModule {
}
