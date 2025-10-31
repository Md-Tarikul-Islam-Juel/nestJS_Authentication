import {User} from '../entities/user.entity';
import {Email} from '../value-objects/email.vo';

export interface UserRepositoryPort {
  findByEmail(email: Email): Promise<User | null>;
  findById(id: number): Promise<User | null>;
  save(user: User): Promise<User>;
  update(user: User): Promise<User>;
  delete(id: number): Promise<void>;
}
