import {Module} from '@nestjs/common';
import {UserService} from './services/user.service';
import {UserController} from './controllers/user.controller';
import {PrismaModule} from "../prisma/prisma.module";
import {LoggerModule} from "../logger/logger.module";
import {JwtConfigModule} from "../jwt/jwt.module";
import {JwtStrategy} from "../jwt/jwt.strategy";

@Module({
    imports: [
        PrismaModule,
        LoggerModule,
        JwtConfigModule
    ],
    providers: [UserService, JwtStrategy],
    controllers: [UserController]
})
export class UserModule {
}
