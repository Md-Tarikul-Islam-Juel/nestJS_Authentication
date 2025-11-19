import { ApolloDriver, ApolloDriverConfig } from '@nestjs/apollo';
import { Module } from '@nestjs/common';
import { APP_FILTER } from '@nestjs/core';
import { GraphQLModule } from '@nestjs/graphql';
import { join } from 'path';
import { GqlExceptionFilter } from './common/graphql/errors/gql-exception.filter';

@Module({
  imports: [
    GraphQLModule.forRoot<ApolloDriverConfig>({
      driver: ApolloDriver,
      autoSchemaFile: join(process.cwd(), 'src/graphql-schema/schema-user.gql'),
      path: '/user',
      context: ({ req, res }) => ({ req, res }),
      buildSchemaOptions: {
        numberScalarMode: 'integer',
      },
      // Allow empty schema during development
      include: [],
    })
  ],
  providers: [
    {
      provide: APP_FILTER,
      useClass: GqlExceptionFilter
    }
  ]
})
export class AppGraphqlModule { }
