import {Inject, Injectable, NotFoundException} from '@nestjs/common';
import {User} from '../../domain/entities/user.entity';
import {UserRepositoryPort} from '../../domain/repositories/user.repository.port';
import {USER_REPOSITORY_PORT} from '../di-tokens';

export interface UpdateUserData {
  firstName?: string;
  lastName?: string;
}

@Injectable()
export class UserService {
  constructor(@Inject(USER_REPOSITORY_PORT) private readonly userRepository: UserRepositoryPort) {}

  async findOneById(id: number): Promise<User> {
    const user = await this.userRepository.findById(id);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  async updateOneById(id: number, data: UpdateUserData): Promise<User> {
    const user = await this.userRepository.findById(id);

    if (!user) {
      throw new NotFoundException('User not found');
    }

    const updatedUser = user.updateProfile(data.firstName, data.lastName);
    return this.userRepository.update(updatedUser);
  }
}
