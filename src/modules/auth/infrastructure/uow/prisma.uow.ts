import {Injectable} from '@nestjs/common';
import {Prisma} from '@prisma/client';
import {PrismaService} from '../../../../platform/prisma/prisma.service';
import {UnitOfWorkPort} from '../../application/uow/uow.port';

@Injectable()
export class PrismaUnitOfWork implements UnitOfWorkPort {
  constructor(private readonly prisma: PrismaService) {}

  async withTransaction<T>(fn: (tx: Prisma.TransactionClient) => Promise<T>): Promise<T> {
    return await Promise.race([
      this.prisma.$transaction(fn, {timeout: 10000}),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error('Database transaction timeout')), 15000))
    ]);
  }
}
