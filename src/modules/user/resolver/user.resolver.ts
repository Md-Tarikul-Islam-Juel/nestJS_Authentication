import { Resolver, Query, Mutation, Args, Context } from '@nestjs/graphql';
import { UseGuards } from '@nestjs/common';
import { User } from '../dto/user.type';
import { UserService } from '../services/user.service';
import { UpdateUserInput } from '../dto/user.input';
import { JweJwtAccessTokenStrategy } from '../../token/strategy/jwe-jwt-access-token.strategy';

@Resolver(() => User)
@UseGuards(JweJwtAccessTokenStrategy)
export class UserResolver {
  constructor(private readonly userService: UserService) {
  }

  @Query(() => User)
  async getUser(@Context() context): Promise<User> {
    const userId = context.req.user.id;
    return this.userService.findOneById(userId);
  }

  @Mutation(() => User)
  async updateUser(@Context() context, @Args('data') data: UpdateUserInput): Promise<User> {
    const userId = context.req.user.id;
    return this.userService.updateOneById(userId, data);
  }
}

