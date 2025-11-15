import {Injectable} from '@nestjs/common';
import {Prisma} from '@prisma/client';
import {PrismaService} from '../../../../platform/prisma/prisma.service';
import {User} from '../../domain/entities/user.entity';
import {UserRepositoryPort} from '../../domain/repositories/user.repository.port';
import {Email} from '../../domain/value-objects/email.vo';
import {UserPrismaMapper} from './user.prisma.mapper';

/**
 * User Prisma Repository
 * Implements DATABASE_STANDARDS.md:
 * - Tx-scoped repository pattern (withTx)
 * - Soft delete (deletedAt)
 * - PII-aware queries (excludes soft-deleted by default)
 */
@Injectable()
export class UserPrismaRepository implements UserRepositoryPort {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Returns a transaction-scoped repository bound to the provided transaction client
   * Following DATABASE_STANDARDS.md: "repo.withTx(tx) returns a repo bound to that tx"
   */
  withTx(tx: Prisma.TransactionClient): UserRepositoryPort {
    return new TransactionScopedUserRepository(tx);
  }

  async findByEmail(email: Email): Promise<User | null> {
    const prismaUser = await this.prisma.user.findFirst({
      where: {
        email: email.getValue(),
        deletedAt: null // Soft delete: exclude deleted rows
      }
    });
    return prismaUser ? UserPrismaMapper.toDomain(prismaUser) : null;
  }

  async findByEmailString(email: string): Promise<User | null> {
    const prismaUser = await this.prisma.user.findFirst({
      where: {
        email,
        deletedAt: null // Soft delete: exclude deleted rows
      }
    });
    return prismaUser ? UserPrismaMapper.toDomain(prismaUser) : null;
  }

  async findById(id: number): Promise<User | null> {
    const prismaUser = await this.prisma.user.findFirst({
      where: {
        id,
        deletedAt: null // Soft delete: exclude deleted rows
      }
    });
    return prismaUser ? UserPrismaMapper.toDomain(prismaUser) : null;
  }

  async save(user: User): Promise<User> {
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
        deletedAt: null, // Not deleted
        isForgetPassword: false
      }
    });
    return UserPrismaMapper.toDomain(prismaUser);
  }

  async update(user: User): Promise<User> {
    const data = UserPrismaMapper.toPersistence(user);

    const prismaUser = await this.prisma.user.update({
      where: {id: user.id},
      data
    });
    return UserPrismaMapper.toDomain(prismaUser);
  }

  async delete(id: number): Promise<void> {
    // Soft delete: set deletedAt instead of removing record
    await this.prisma.user.update({
      where: {id},
      data: {
        deletedAt: new Date()
      }
    });
  }

  async hardDelete(id: number): Promise<void> {
    // Permanent delete: removes record from database
    await this.prisma.user.delete({
      where: {id}
    });
  }

  async updateVerificationStatus(id: number, verified: boolean): Promise<User> {
    const prismaUser = await this.prisma.user.update({
      where: {id},
      data: {verified}
    });
    return UserPrismaMapper.toDomain(prismaUser);
  }

  async updateForgotPasswordStatus(id: number, isForgetPassword: boolean): Promise<User> {
    const prismaUser = await this.prisma.user.update({
      where: {id},
      data: {isForgetPassword}
    });
    return UserPrismaMapper.toDomain(prismaUser);
  }

  async updateLogoutPin(id: number, logoutPin: string): Promise<User> {
    const prismaUser = await this.prisma.user.update({
      where: {id},
      data: {logoutPin}
    });
    return UserPrismaMapper.toDomain(prismaUser);
  }

  async updateLastActivityAt(id: number, lastActivityAt: Date): Promise<User> {
    const prismaUser = await this.prisma.user.update({
      where: {id},
      data: {lastActivityAt}
    });
    return UserPrismaMapper.toDomain(prismaUser);
  }

  async updateOtpAttempts(id: number, failedOtpAttempts: number, accountLockedUntil: Date | null): Promise<User> {
    const prismaUser = await this.prisma.user.update({
      where: {id},
      data: {
        failedOtpAttempts,
        accountLockedUntil
      }
    });
    return UserPrismaMapper.toDomain(prismaUser);
  }

  async getLogoutPin(id: number): Promise<string | null> {
    const prismaUser = await this.prisma.user.findFirst({
      where: {
        id,
        deletedAt: null // Soft delete: exclude deleted rows
      },
      select: {logoutPin: true}
    });
    return prismaUser ? prismaUser.logoutPin : null;
  }
}

/**
 * Transaction-scoped repository implementation
 * All operations are bound to the provided transaction client
 */
class TransactionScopedUserRepository implements UserRepositoryPort {
  constructor(private readonly tx: Prisma.TransactionClient) {}

  withTx(tx: Prisma.TransactionClient): UserRepositoryPort {
    // Already in a transaction, return new scoped instance
    return new TransactionScopedUserRepository(tx);
  }

  async findByEmail(email: Email): Promise<User | null> {
    const prismaUser = await this.tx.user.findFirst({
      where: {
        email: email.getValue(),
        deletedAt: null // Soft delete: exclude deleted rows
      }
    });
    return prismaUser ? UserPrismaMapper.toDomain(prismaUser) : null;
  }

  async findByEmailString(email: string): Promise<User | null> {
    const prismaUser = await this.tx.user.findFirst({
      where: {
        email,
        deletedAt: null // Soft delete: exclude deleted rows
      }
    });
    return prismaUser ? UserPrismaMapper.toDomain(prismaUser) : null;
  }

  async findById(id: number): Promise<User | null> {
    const prismaUser = await this.tx.user.findFirst({
      where: {
        id,
        deletedAt: null // Soft delete: exclude deleted rows
      }
    });
    return prismaUser ? UserPrismaMapper.toDomain(prismaUser) : null;
  }

  async save(user: User): Promise<User> {
    const prismaUser = await this.tx.user.create({
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
        deletedAt: null, // Not deleted
        isForgetPassword: false
      }
    });
    return UserPrismaMapper.toDomain(prismaUser);
  }

  async update(user: User): Promise<User> {
    const data = UserPrismaMapper.toPersistence(user);

    const prismaUser = await this.tx.user.update({
      where: {id: user.id},
      data
    });
    return UserPrismaMapper.toDomain(prismaUser);
  }

  async delete(id: number): Promise<void> {
    // Soft delete: set deletedAt instead of removing record
    await this.tx.user.update({
      where: {id},
      data: {
        deletedAt: new Date()
      }
    });
  }

  async hardDelete(id: number): Promise<void> {
    // Permanent delete: removes record from database
    await this.tx.user.delete({
      where: {id}
    });
  }

  async updateVerificationStatus(id: number, verified: boolean): Promise<User> {
    const prismaUser = await this.tx.user.update({
      where: {id},
      data: {verified}
    });
    return UserPrismaMapper.toDomain(prismaUser);
  }

  async updateForgotPasswordStatus(id: number, isForgetPassword: boolean): Promise<User> {
    const prismaUser = await this.tx.user.update({
      where: {id},
      data: {isForgetPassword}
    });
    return UserPrismaMapper.toDomain(prismaUser);
  }

  async updateLogoutPin(id: number, logoutPin: string): Promise<User> {
    const prismaUser = await this.tx.user.update({
      where: {id},
      data: {logoutPin}
    });
    return UserPrismaMapper.toDomain(prismaUser);
  }

  async updateLastActivityAt(id: number, lastActivityAt: Date): Promise<User> {
    const prismaUser = await this.tx.user.update({
      where: {id},
      data: {lastActivityAt}
    });
    return UserPrismaMapper.toDomain(prismaUser);
  }

  async updateOtpAttempts(id: number, failedOtpAttempts: number, accountLockedUntil: Date | null): Promise<User> {
    const prismaUser = await this.tx.user.update({
      where: {id},
      data: {
        failedOtpAttempts,
        accountLockedUntil
      }
    });
    return UserPrismaMapper.toDomain(prismaUser);
  }

  async getLogoutPin(id: number): Promise<string | null> {
    const prismaUser = await this.tx.user.findFirst({
      where: {
        id,
        deletedAt: null // Soft delete: exclude deleted rows
      },
      select: {logoutPin: true}
    });
    return prismaUser ? prismaUser.logoutPin : null;
  }
}
