import {Prisma} from '@prisma/client';

export interface UnitOfWorkPort {
  withTransaction<T>(fn: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T>;
}
