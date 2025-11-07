import {Prisma} from '@prisma/client';
import {User} from '../entities/user.entity';
import {Email} from '../value-objects/email.vo';

/**
 * Repository Port following DATABASE_STANDARDS.md
 * Supports transaction-scoped operations via withTx()
 * All database queries MUST go through this repository (no direct Prisma access in services)
 */
export interface UserRepositoryPort {
  findByEmail(email: Email): Promise<User | null>;
  findByEmailString(email: string): Promise<User | null>; // Convenience method for string emails
  findById(id: number): Promise<User | null>;
  save(user: User): Promise<User>;
  update(user: User): Promise<User>;
  delete(id: number): Promise<void>; // Soft delete (sets deletedAt)
  hardDelete(id: number): Promise<void>; // Permanent delete (removes record)

  // Partial update methods for common operations
  updateVerificationStatus(id: number, verified: boolean): Promise<User>;
  updateForgotPasswordStatus(id: number, isForgetPassword: boolean): Promise<User>;
  updateLogoutPin(id: number, logoutPin: string): Promise<User>;
  updateLastActivityAt(id: number, lastActivityAt: Date): Promise<User>;
  updateOtpAttempts(id: number, failedOtpAttempts: number, accountLockedUntil: Date | null): Promise<User>;
  getLogoutPin(id: number): Promise<string | null>;

  /**
   * Returns a transaction-scoped repository bound to the provided transaction client
   * Following DATABASE_STANDARDS.md: "repo.withTx(tx) returns a repo bound to that tx"
   */
  withTx(tx: Prisma.TransactionClient): UserRepositoryPort;
}
