import {User as PrismaUser} from '@prisma/client';
import {Email} from '../../../auth/domain/value-objects/email.vo';
import {User} from '../../domain/entities/user.entity';

export class UserPrismaMapper {
  static toDomain(prismaUser: Pick<PrismaUser, 'id' | 'email' | 'firstName' | 'lastName'>): User {
    return new User(prismaUser.id, Email.create(prismaUser.email), prismaUser.firstName, prismaUser.lastName);
  }

  static toPersistence(domainUser: User): Partial<PrismaUser> {
    return {
      id: domainUser.id,
      email: domainUser.email.getValue(),
      firstName: domainUser.firstName,
      lastName: domainUser.lastName
    };
  }
}
