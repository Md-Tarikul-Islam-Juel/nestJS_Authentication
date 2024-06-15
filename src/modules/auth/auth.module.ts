import {Module} from '@nestjs/common';
import {PrismaModule} from 'src/modules/prisma/prisma.module';
import {AuthController} from './controllers/auth.controller';
import {LoggerModule} from "../logger/logger.module";
import {AuthService} from "./services/auth.service";
import {JwtConfigModule} from "../jwe-jwt/jwe-jwt.module";
import { JweJwtAccessTokenStrategy } from '../jwe-jwt/jwe-jwt-access-token.strategy';
import { JweJwtRefreshTokenStrategy } from '../jwe-jwt/jwe-jwt-refresh-token.strategy';
import { GoogleStrategy } from './strategy/google.strategy';
import { FacebookStrategy } from './strategy/facebook.strategy';


@Module({
    imports: [
        PrismaModule,
        LoggerModule,
        JwtConfigModule,
    ],
    controllers: [AuthController],
    providers: [AuthService, JweJwtAccessTokenStrategy, JweJwtRefreshTokenStrategy, GoogleStrategy, FacebookStrategy],
    exports: [AuthService],
})
export class AuthModule {
}
