import {UseGuards} from '@nestjs/common';
import {Args, Context, Mutation, Query, Resolver} from '@nestjs/graphql';
import {UpdateUserInput} from '../../../../modules/user/dto/user.input';
import {User as GraphQLUser} from '../../../../modules/user/dto/user.type';
import {JweJwtAccessTokenStrategy} from '../../../token/strategy/jwe-jwt-access-token.strategy';
import {UserMapper} from '../../application/mappers/user.mapper';
import {UserService} from '../../application/services/user.service';

@Resolver(() => GraphQLUser)
@UseGuards(JweJwtAccessTokenStrategy)
export class UsersResolver {
  constructor(private readonly userService: UserService) {}

  @Query(() => GraphQLUser)
  async getUser(@Context() context): Promise<GraphQLUser> {
    const userId = context.req.user.id;
    const user = await this.userService.findOneById(userId);
    return UserMapper.toGraphQL(user);
  }

  @Mutation(() => GraphQLUser)
  async updateUser(@Context() context, @Args('data') data: UpdateUserInput): Promise<GraphQLUser> {
    const userId = context.req.user.id;
    const user = await this.userService.updateOneById(userId, data);
    return UserMapper.toGraphQL(user);
  }
}
