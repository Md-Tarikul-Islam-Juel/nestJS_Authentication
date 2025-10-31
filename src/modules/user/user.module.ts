import {ApolloDriver, ApolloDriverConfig} from '@nestjs/apollo';
import {Module} from '@nestjs/common';
import {GraphQLModule} from '@nestjs/graphql';
import {join} from 'path';
import {LoggerModule} from '../../common/observability/logger.module';
import {PrismaModule} from '../../platform/prisma/prisma.module';
import {JwtConfigModule} from '../token/jwe-jwt.module';
import {JweJwtAccessTokenStrategy} from '../token/strategy/jwe-jwt-access-token.strategy';
import {UserResolver} from './resolver/user.resolver';
import {UserService} from './services/user.service';

@Module({
  imports: [
    PrismaModule,
    LoggerModule,
    JwtConfigModule,
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: join(process.cwd(), 'src/graphql-schema/schema-user.gql'),
      path: '/user',
      context: ({req, res}) => ({req, res})
    })
  ],
  providers: [UserService, JweJwtAccessTokenStrategy, UserResolver]
})
export class UserModule {}
