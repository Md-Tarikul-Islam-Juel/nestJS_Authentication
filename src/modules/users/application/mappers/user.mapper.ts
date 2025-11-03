import {User} from '../../domain/entities/user.entity';
import {User as GraphQLUser} from '../../interface/graphql/users.types';

export class UserMapper {
  static toGraphQL(domainUser: User): GraphQLUser {
    return {
      id: domainUser.id,
      email: domainUser.email.getValue(),
      firstName: domainUser.firstName ?? undefined,
      lastName: domainUser.lastName ?? undefined
    };
  }
}
