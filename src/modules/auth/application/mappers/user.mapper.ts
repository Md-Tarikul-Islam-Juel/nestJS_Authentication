import {User} from '../../domain/entities/user.entity';
import {SignInResponseUserDto, SignupResponseUserDto} from '../dto/auth-response.dto';

export class UserMapper {
  static toSignInResponse(domainUser: User): SignInResponseUserDto {
    return {
      id: domainUser.id,
      email: domainUser.email.getValue(),
      firstName: domainUser.firstName || '',
      lastName: domainUser.lastName || ''
    };
  }

  static toSignupResponse(domainUser: User): SignupResponseUserDto {
    return {
      id: domainUser.id,
      email: domainUser.email.getValue(),
      firstName: domainUser.firstName || '',
      lastName: domainUser.lastName || ''
    };
  }
}
