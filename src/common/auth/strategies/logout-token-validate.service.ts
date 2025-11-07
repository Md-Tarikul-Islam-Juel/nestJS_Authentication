import {Inject, Injectable} from '@nestjs/common';
import {USER_REPOSITORY_PORT} from '../../../modules/auth/application/di-tokens';
import {UserRepositoryPort} from '../../../modules/auth/domain/repositories/user.repository.port';

/**
 * Logout Token Validation Service
 * Validates logout pin for token revocation
 * Following Clean Architecture: all database queries go through repository
 */
@Injectable()
export class LogoutTokenValidateService {
  constructor(
    @Inject(USER_REPOSITORY_PORT)
    private readonly userRepository: UserRepositoryPort
  ) {}

  async getLogoutPinById(userId: number): Promise<string | null> {
    // Following Clean Architecture: all database queries go through repository
    return this.userRepository.getLogoutPin(userId);
  }
}
