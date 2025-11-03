import {UseGuards} from '@nestjs/common';
import {Args, Context, Mutation, Query, Resolver} from '@nestjs/graphql';
import {AccessTokenStrategy} from '../../../../common/auth/strategies/access-token.strategy';
import {UserMapper} from '../../application/mappers/user.mapper';
import {UserService} from '../../application/services/user.service';
import {UpdateUserInput} from './users.inputs';
import {User} from './users.types';

@Resolver(() => User)
@UseGuards(AccessTokenStrategy)
export class UsersResolver {
  constructor(private readonly userService: UserService) {}

  @Query(() => User)
  async getUser(@Context() context): Promise<User> {
    const userId = context.req.user.id;
    const user = await this.userService.findOneById(userId);
    return UserMapper.toGraphQL(user);
  }

  @Mutation(() => User)
  async updateUser(@Context() context, @Args('data') data: UpdateUserInput): Promise<User> {
    const userId = context.req.user.id;
    const user = await this.userService.updateOneById(userId, data);
    return UserMapper.toGraphQL(user);
  }
}
