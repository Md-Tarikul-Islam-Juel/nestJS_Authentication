import {Module} from '@nestjs/common';
import {LoggerModule} from '../../common/observability/logger.module';
import {PrismaModule} from '../../platform/prisma/prisma.module';
import {JwtConfigModule} from '../token/jwe-jwt.module';
import {JweJwtAccessTokenStrategy} from '../token/strategy/jwe-jwt-access-token.strategy';
import {USER_REPOSITORY_PORT} from './application/di-tokens';
import {UserService} from './application/services/user.service';
import {UserPrismaRepository} from './infrastructure/prisma/user.prisma.repository';
import {UsersResolver} from './interface/graphql/users.resolver';

@Module({
  imports: [PrismaModule, LoggerModule, JwtConfigModule],
  providers: [
    {
      provide: USER_REPOSITORY_PORT,
      useClass: UserPrismaRepository
    },
    UserPrismaRepository,
    UserService,
    UsersResolver,
    JweJwtAccessTokenStrategy
  ],
  exports: [UserService]
})
export class UsersModule {}
