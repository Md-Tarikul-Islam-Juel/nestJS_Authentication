import {Injectable} from '@nestjs/common';
import {PrismaService} from '../../prisma/prisma.service';
import {CommonAuthService} from './commonAuth.service';

@Injectable()
export class LogoutService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly commonAuthService: CommonAuthService
  ) {}

  async logoutFromAllDevices(userId: number): Promise<string> {
    const newLogoutPin = this.commonAuthService.generateOtp(6);
    await this.prisma.user.update({
      where: {id: userId},
      data: {logoutPin: newLogoutPin}
    });
    return 'Successfully logged out from all devices.';
  }
}
