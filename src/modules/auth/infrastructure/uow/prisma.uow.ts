import {Injectable} from '@nestjs/common';
import {Prisma} from '@prisma/client';
import {UnitOfWorkPort} from '../../../../common/persistence/uow/uow.port';
import {PrismaService} from '../../../../platform/prisma/prisma.service';

/**
 * Prisma Unit of Work Implementation
 * Following DATABASE_STANDARDS.md:
 * - Central transaction boundary
 * - Isolation level configuration
 * - Retry logic for transient failures
 * - Timeout handling
 */
@Injectable()
export class PrismaUnitOfWork implements UnitOfWorkPort {
  private readonly maxRetries = 3;
  private readonly retryDelay = 100; // ms
  private readonly transactionTimeout = 10000; // 10 seconds

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Executes a function within a transaction with retry logic and proper isolation level
   * Following DATABASE_STANDARDS.md: "uow.withTransaction(fn: (tx: Prisma.TransactionClient) => Promise<T>)"
   */
  async withTransaction<T>(
    fn: (tx: Prisma.TransactionClient) => Promise<T>,
    options?: {
      isolationLevel?: Prisma.TransactionIsolationLevel;
      maxWait?: number;
      timeout?: number;
    }
  ): Promise<T> {
    const isolationLevel = options?.isolationLevel ?? Prisma.TransactionIsolationLevel.ReadCommitted;
    const maxWait = options?.maxWait ?? 5000;
    const timeout = options?.timeout ?? this.transactionTimeout;

    let lastError: Error | unknown;

    // Retry logic for transient failures
    for (let attempt = 0; attempt < this.maxRetries; attempt++) {
      try {
        return await Promise.race([
          this.prisma.$transaction(fn, {
            isolationLevel,
            maxWait,
            timeout
          }),
          new Promise<never>((_, reject) => setTimeout(() => reject(new Error(`Database transaction timeout after ${timeout}ms`)), timeout + 1000))
        ]);
      } catch (error) {
        lastError = error;

        // Don't retry on non-transient errors
        if (this.isNonRetryableError(error)) {
          throw error;
        }

        // Exponential backoff: wait before retry
        if (attempt < this.maxRetries - 1) {
          await this.delay(this.retryDelay * Math.pow(2, attempt));
        }
      }
    }

    // All retries exhausted
    throw lastError;
  }

  /**
   * Determines if an error is non-retryable (e.g., validation errors, constraint violations)
   */
  private isNonRetryableError(error: unknown): boolean {
    if (error instanceof Prisma.PrismaClientKnownRequestError) {
      // Don't retry on constraint violations, validation errors, etc.
      const nonRetryableCodes = ['P2002', 'P2003', 'P2025', 'P2014'];
      return nonRetryableCodes.includes(error.code);
    }
    // Non-Prisma errors (e.g., timeout) are retryable
    return false;
  }

  /**
   * Delay helper for retry backoff
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
