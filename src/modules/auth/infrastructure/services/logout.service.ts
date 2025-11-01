import {Injectable} from '@nestjs/common';
import {PrismaService} from '../../../../platform/prisma/prisma.service';
import {UserNotFoundError} from '../../domain/errors/user-not-found.error';
import {OtpDomainService} from '../../domain/services/otp-domain.service';

@Injectable()
export class LogoutService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly otpDomainService: OtpDomainService
  ) {}

  async logoutFromAllDevices(userId: number): Promise<string> {
    // Verify user exists
    const user = await this.prisma.user.findUnique({
      where: {id: userId},
      select: {id: true}
    });

    if (!user) {
      throw new UserNotFoundError();
    }

    // Generate new logoutPin to invalidate all existing refresh tokens
    const newLogoutPin = this.otpDomainService.generateOtp(6);

    await this.prisma.user.update({
      where: {id: userId},
      data: {logoutPin: newLogoutPin}
    });

    return 'Successfully logged out from all devices.';
  }
}
