import { HttpException, HttpStatus, Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma/prisma.service';
import { LoggerService } from '../../logger/logger.service';
import { userNotFound } from '../utils/string';


@Injectable()
export class UserService {
  constructor(
    private readonly prisma: PrismaService,
    private logger: LoggerService,
  ) {
  }

  async me(req: any) {
    try {
      const user = await this.prisma.user.findUnique({
        where: {
          email: req.user.email,
        },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
        },
      });

      if (!user) {
        this.logger.error({
          message: userNotFound,
          details: req.user.email,
        });
        throw new HttpException(userNotFound, HttpStatus.NOT_FOUND);
      }

      return { success: true, data: user };
    } catch (error) {
      this.logger.error({
        message: 'An error occurred while retrieving user data.',
        details: req.user.email,
      });
      throw new HttpException('An error occurred while retrieving user data.', HttpStatus.INTERNAL_SERVER_ERROR);
    }
  }
}
