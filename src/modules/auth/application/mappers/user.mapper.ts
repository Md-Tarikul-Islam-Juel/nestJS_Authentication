import {User} from '../../domain/entities/user.entity';
import {SignInResponseUserDto, SignupResponseUserDto} from '../dto/auth-response.dto';

export type UserMapperInput = {
  id: number;
  email: string;
  firstName?: string | null;
  lastName?: string | null;
  createdAt?: Date;
};

export class UserMapper {
  static toSignInResponse(user: User | UserMapperInput): SignInResponseUserDto {
    const email = user instanceof User ? user.email.getValue() : user.email;

    return {
      id: user.id,
      email,
      firstName: (user.firstName ?? '') || '',
      lastName: (user.lastName ?? '') || ''
    };
  }

  static toSignupResponse(user: User | UserMapperInput): SignupResponseUserDto {
    const email = user instanceof User ? user.email.getValue() : user.email;

    return {
      id: user.id,
      email,
      firstName: (user.firstName ?? '') || '',
      lastName: (user.lastName ?? '') || '',
      createdAt: user.createdAt
    };
  }
}
