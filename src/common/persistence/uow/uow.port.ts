import {Prisma} from '@prisma/client';

/**
 * Unit of Work Port
 * Following DATABASE_STANDARDS.md:
 * - Central transaction boundary
 * - API: uow.withTransaction(fn: (tx: Prisma.TransactionClient) => Promise<T>)
 *
 * This is a shared port used across all modules for transaction management.
 * Module-specific implementations should be in: src/modules/{module}/infrastructure/uow/
 */
export interface UnitOfWorkPort {
  withTransaction<T>(
    fn: (tx: Prisma.TransactionClient) => Promise<T>,
    options?: {
      isolationLevel?: Prisma.TransactionIsolationLevel;
      maxWait?: number;
      timeout?: number;
    }
  ): Promise<T>;
}
