import {Injectable} from '@nestjs/common';
import {PrismaService} from '../../../../platform/prisma/prisma.service';
import {OtpDomainService} from '../../domain/services/otp-domain.service';

@Injectable()
export class LogoutService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly otpDomainService: OtpDomainService
  ) {}

  async logoutFromAllDevices(userId: number): Promise<string> {
    const newLogoutPin = this.otpDomainService.generateOtp(6);
    await this.prisma.user.update({
      where: {id: userId},
      data: {logoutPin: newLogoutPin}
    });
    return 'Successfully logged out from all devices.';
  }
}
