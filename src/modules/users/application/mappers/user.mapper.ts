import {User as GraphQLUser} from '../../../../modules/user/dto/user.type';
import {User} from '../../domain/entities/user.entity';

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
