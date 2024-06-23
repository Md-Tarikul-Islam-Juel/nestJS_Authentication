import { Module } from '@nestjs/common';
import { UserService } from './services/user.service';
import { PrismaModule } from '../prisma/prisma.module';
import { LoggerModule } from '../logger/logger.module';
import { JwtConfigModule } from '../jwe-jwt/jwe-jwt.module';
import { JweJwtAccessTokenStrategy } from '../jwe-jwt/jwe-jwt-access-token.strategy';
import { GraphQLModule } from '@nestjs/graphql';
import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { UserResolver } from './resolver/user.resolver';
import { join } from 'path';

@Module({
  imports: [
    PrismaModule,
    LoggerModule,
    JwtConfigModule,
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: join(process.cwd(), 'src/graphql-schema/schema-user.gql'),
      path: '/user',
      context: ({ req, res }) => ({ req, res }),
    }),
  ],
  providers: [
    UserService,
    JweJwtAccessTokenStrategy,
    UserResolver,
  ],
})
export class UserModule {
}
