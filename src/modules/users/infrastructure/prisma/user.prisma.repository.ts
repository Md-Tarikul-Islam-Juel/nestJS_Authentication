import {Injectable} from '@nestjs/common';
import {PrismaService} from '../../../../platform/prisma/prisma.service';
import {User} from '../../domain/entities/user.entity';
import {UserRepositoryPort} from '../../domain/repositories/user.repository.port';
import {UserPrismaMapper} from './user.prisma.mapper';

@Injectable()
export class UserPrismaRepository implements UserRepositoryPort {
  constructor(private readonly prisma: PrismaService) {}

  async findById(id: number): Promise<User | null> {
    const prismaUser = await this.prisma.user.findUnique({
      where: {id},
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true
      }
    });

    return prismaUser ? UserPrismaMapper.toDomain(prismaUser) : null;
  }

  async update(user: User): Promise<User> {
    const prismaUser = await this.prisma.user.update({
      where: {id: user.id},
      data: {
        firstName: user.firstName,
        lastName: user.lastName
      }
    });

    return UserPrismaMapper.toDomain(prismaUser);
  }
}
