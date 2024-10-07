import {Injectable} from '@nestjs/common';
import {PrismaService} from '../../prisma/prisma.service';

@Injectable()
export class LogoutTokenValidateService {
  constructor(private readonly prisma: PrismaService) {}

  async getLogoutPinById(userId: number): Promise<string | null> {
    const user = await this.prisma.user.findUnique({
      where: {id: userId},
      select: {logoutPin: true}
    });

    return user ? user.logoutPin : null;
  }
}
