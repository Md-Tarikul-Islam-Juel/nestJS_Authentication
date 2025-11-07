import {Inject, Injectable} from '@nestjs/common';
import {USER_REPOSITORY_PORT} from '../../application/di-tokens';
import {UserNotFoundError} from '../../domain/errors/user-not-found.error';
import {UserRepositoryPort} from '../../domain/repositories/user.repository.port';
import {OtpDomainService} from '../../domain/services/otp-domain.service';

/**
 * Logout Service
 * Following Clean Architecture: all database queries go through repository
 */
@Injectable()
export class LogoutService {
  constructor(
    @Inject(USER_REPOSITORY_PORT)
    private readonly userRepository: UserRepositoryPort,
    private readonly otpDomainService: OtpDomainService
  ) {}

  async logoutFromAllDevices(userId: number): Promise<string> {
    // Following Clean Architecture: all database queries go through repository
    // Verify user exists and is not soft-deleted
    const user = await this.userRepository.findById(userId);

    if (!user) {
      throw new UserNotFoundError();
    }

    // Generate new logoutPin to invalidate all existing refresh tokens
    const newLogoutPin = this.otpDomainService.generateOtp(6);

    await this.userRepository.updateLogoutPin(userId, newLogoutPin);

    return 'Successfully logged out from all devices.';
  }
}
