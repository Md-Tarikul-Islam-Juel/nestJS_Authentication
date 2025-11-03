import {Injectable} from '@nestjs/common';
import {PrismaService} from '../../../platform/prisma/prisma.service';

/**
 * Logout Token Validation Service
 * Validates logout pin for token revocation
 */
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

