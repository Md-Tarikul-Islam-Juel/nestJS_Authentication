import {Module} from '@nestjs/common';
import {PrismaModule} from 'src/modules/prisma/prisma.module';
import {AuthController} from './controllers/auth.controller';
import {LoggerModule} from "../logger/logger.module";
import {AuthService} from "./services/auth.service";
import {JwtConfigModule} from "../jwt/jwt.module";
import {JwtStrategy} from "../jwt/jwt.strategy";

@Module({
    imports: [
        PrismaModule,
        LoggerModule,
        JwtConfigModule
    ],
    controllers: [AuthController],
    providers: [AuthService, JwtStrategy],
    exports: [AuthService],
})
export class AuthModule {
}
