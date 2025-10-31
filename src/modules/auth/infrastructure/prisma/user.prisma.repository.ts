import {Injectable} from '@nestjs/common';
import {PrismaService} from '../../../../platform/prisma/prisma.service';
import {User} from '../../domain/entities/user.entity';
import {UserRepositoryPort} from '../../domain/repositories/user.repository.port';
import {Email} from '../../domain/value-objects/email.vo';
import {UserPrismaMapper} from './user.prisma.mapper';

@Injectable()
export class UserPrismaRepository implements UserRepositoryPort {
  constructor(private readonly prisma: PrismaService) {}

  async findByEmail(email: Email): Promise<User | null> {
    const prismaUser = await this.prisma.user.findUnique({
      where: {email: email.getValue()}
    });
    return prismaUser ? UserPrismaMapper.toDomain(prismaUser) : null;
  }

  async findById(id: number): Promise<User | null> {
    const prismaUser = await this.prisma.user.findUnique({
      where: {id}
    });
    return prismaUser ? UserPrismaMapper.toDomain(prismaUser) : null;
  }

  async save(user: User): Promise<User> {
    const data = UserPrismaMapper.toPersistence(user);
    const prismaUser = await this.prisma.user.create({
      data: {
        email: user.email.getValue(),
        password: user.getPassword().getHashedValue(),
        firstName: user.firstName,
        lastName: user.lastName,
        verified: user.verified,
        loginSource: user.loginSource,
        authorizerId: user.authorizerId,
        mfaEnabled: user.mfaEnabled,
        failedOtpAttempts: user.failedOtpAttempts,
        accountLockedUntil: user.accountLockedUntil,
        lastActivityAt: user.lastActivityAt,
        logoutPin: user.logoutPin,
        isForgetPassword: false // Default value since User entity doesn't track this
      }
    });
    return UserPrismaMapper.toDomain(prismaUser);
  }

  async update(user: User): Promise<User> {
    const data = UserPrismaMapper.toPersistence(user);
    const prismaUser = await this.prisma.user.update({
      where: {id: user.id},
      data: {
        email: user.email.getValue(),
        password: user.getPassword().getHashedValue(),
        firstName: user.firstName,
        lastName: user.lastName,
        verified: user.verified,
        loginSource: user.loginSource,
        authorizerId: user.authorizerId,
        mfaEnabled: user.mfaEnabled,
        failedOtpAttempts: user.failedOtpAttempts,
        accountLockedUntil: user.accountLockedUntil,
        lastActivityAt: user.lastActivityAt,
        logoutPin: user.logoutPin,
        isForgetPassword: false // Default value since User entity doesn't track this
      }
    });
    return UserPrismaMapper.toDomain(prismaUser);
  }

  async delete(id: number): Promise<void> {
    await this.prisma.user.delete({
      where: {id}
    });
  }
}
