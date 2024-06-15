import {Module} from '@nestjs/common';
import {UserService} from './services/user.service';
import {UserController} from './controllers/user.controller';
import {PrismaModule} from "../prisma/prisma.module";
import {LoggerModule} from "../logger/logger.module";
import {JwtConfigModule} from "../jwe-jwt/jwe-jwt.module";
import { JweJwtAccessTokenStrategy } from '../jwe-jwt/jwe-jwt-access-token.strategy';


@Module({
    imports: [
        PrismaModule,
        LoggerModule,
        JwtConfigModule
    ],
    providers: [UserService, JweJwtAccessTokenStrategy],
    controllers: [UserController]
})
export class UserModule {
}
