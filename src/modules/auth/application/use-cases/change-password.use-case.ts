import {Inject, Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {UNIT_OF_WORK_PORT} from '../../../../common/persistence/uow/di-tokens';
import {UnitOfWorkPort} from '../../../../common/persistence/uow/uow.port';
import {AUTH_MESSAGES} from '../../../_shared/constants';
import {InvalidCredentialsError} from '../../domain/errors/invalid-credentials.error';
import {UserNotFoundError} from '../../domain/errors/user-not-found.error';
import {PasswordPolicyService} from '../../domain/services/password-policy.service';
import {UserService} from '../../infrastructure/services/user.service';
import {ChangePasswordCommand} from '../commands/change-password.command';
import {ChangePasswordSuccessResponseDto} from '../dto/auth-response.dto';

@Injectable()
export class ChangePasswordUseCase {
  private readonly saltRounds: number;

  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UserService,
    private readonly passwordService: PasswordPolicyService,
    @Inject(UNIT_OF_WORK_PORT)
    private readonly uow: UnitOfWorkPort
  ) {
    this.saltRounds = this.configService.get<number>('authConfig.bcryptSaltRounds');
  }

  async execute(command: ChangePasswordCommand): Promise<ChangePasswordSuccessResponseDto> {
    // Fetch user BEFORE transaction to validate everything first
    const existingUser = await this.userService.findUserByEmail(command.email || '');

    if (!existingUser || existingUser.id !== command.userId) {
      throw new UserNotFoundError();
    }

    // Validate old password for non-forget-password flows
    if (!command.isForgetPassword) {
      // Check if old password is provided
      if (!command.oldPassword) {
        throw new InvalidCredentialsError();
      }

      // Validate that new password is different from old password (plain text comparison)
      if (command.oldPassword === command.newPassword) {
        throw new InvalidCredentialsError();
      }

      // Verify old password matches current password and user is verified
      await this.userService.verifyUserAndChangePassword(
        existingUser,
        {oldPassword: command.oldPassword, newPassword: command.newPassword},
        {user: {isForgetPassword: false}}
      );

      // Verify new password is different from current password (hashed comparison)
      const isNewPasswordSameAsCurrent = await this.passwordService.comparePassword(command.newPassword, existingUser.password);
      if (isNewPasswordSameAsCurrent) {
        throw new InvalidCredentialsError();
      }
    } else {
      // For forget password flow, verify user is verified (old password validation is skipped)
      await this.userService.verifyUserAndChangePassword(existingUser, {newPassword: command.newPassword}, {user: {isForgetPassword: true}});

      // For forget password, also verify new password is different from current password
      const isNewPasswordSameAsCurrent = await this.passwordService.comparePassword(command.newPassword, existingUser.password);
      if (isNewPasswordSameAsCurrent) {
        throw new InvalidCredentialsError();
      }
    }

    // Only enter transaction AFTER all validations pass
    return await this.uow.withTransaction(async tx => {
      // Hash and update the password
      const hashedPassword = await this.passwordService.hashPassword(command.newPassword, this.saltRounds);
      await tx.user.update({
        where: {
          id: command.userId,
          deletedAt: null // Soft delete: only update active users
        },
        data: {
          password: hashedPassword,
          isForgetPassword: false
        }
      });

      return {
        success: true,
        message: AUTH_MESSAGES.PASSWORD_UPDATED
      };
    });
  }
}
