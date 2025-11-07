import {User as PrismaUser} from '@prisma/client';
import {User} from '../../domain/entities/user.entity';
import {Email} from '../../domain/value-objects/email.vo';
import {Password} from '../../domain/value-objects/password.vo';

export class UserPrismaMapper {
  static toDomain(prismaUser: PrismaUser): User {
    return new User(
      prismaUser.id,
      Email.create(prismaUser.email),
      Password.create(prismaUser.password),
      prismaUser.firstName,
      prismaUser.lastName,
      prismaUser.verified,
      prismaUser.loginSource,
      prismaUser.authorizerId,
      prismaUser.mfaEnabled,
      prismaUser.failedOtpAttempts,
      prismaUser.accountLockedUntil,
      prismaUser.lastActivityAt,
      prismaUser.logoutPin,
      prismaUser.deletedAt,
      prismaUser.createdAt,
      prismaUser.updatedAt
    );
  }

  static toPersistence(domainUser: User): Partial<PrismaUser> {
    return {
      id: domainUser.id,
      email: domainUser.email.getValue(),
      password: domainUser.getPassword().getHashedValue(),
      firstName: domainUser.firstName,
      lastName: domainUser.lastName,
      verified: domainUser.verified,
      loginSource: domainUser.loginSource,
      authorizerId: domainUser.authorizerId,
      mfaEnabled: domainUser.mfaEnabled,
      failedOtpAttempts: domainUser.failedOtpAttempts,
      accountLockedUntil: domainUser.accountLockedUntil,
      lastActivityAt: domainUser.lastActivityAt,
      logoutPin: domainUser.logoutPin,
      deletedAt: domainUser.deletedAt,
      createdAt: domainUser.createdAt,
      updatedAt: domainUser.updatedAt
    };
  }
}
