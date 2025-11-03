import {Module} from '@nestjs/common';
import {AccessTokenStrategy} from '../../common/auth/strategies/access-token.strategy';
import {LoggerModule} from '../../common/observability/logger.module';
import {PlatformJwtModule} from '../../platform/jwt/jwt.module';
import {PrismaModule} from '../../platform/prisma/prisma.module';
import {USER_REPOSITORY_PORT} from './application/di-tokens';
import {UserService} from './application/services/user.service';
import {UserPrismaRepository} from './infrastructure/prisma/user.prisma.repository';
import {UsersResolver} from './interface/graphql/users.resolver';

@Module({
  imports: [PrismaModule, LoggerModule, PlatformJwtModule],
  providers: [
    {
      provide: USER_REPOSITORY_PORT,
      useClass: UserPrismaRepository
    },
    UserPrismaRepository,
    UserService,
    UsersResolver,
    AccessTokenStrategy
  ],
  exports: [UserService]
})
export class UsersModule {}
