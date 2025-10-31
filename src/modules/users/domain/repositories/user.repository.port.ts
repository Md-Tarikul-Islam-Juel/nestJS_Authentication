import {User} from '../entities/user.entity';

export interface UserRepositoryPort {
  findById(id: number): Promise<User | null>;
  update(user: User): Promise<User>;
}
