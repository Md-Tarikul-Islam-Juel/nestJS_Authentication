import {Inject, Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {AUTH_MESSAGES} from '../../../_shared/constants';
import {UserNotFoundError} from '../../domain/errors/user-not-found.error';
import {PasswordPolicyService} from '../../domain/services/password-policy.service';
import {UserService} from '../../infrastructure/services/user.service';
import {ChangePasswordCommand} from '../commands/change-password.command';
import {UNIT_OF_WORK_PORT} from '../di-tokens';
import {ChangePasswordSuccessResponseDto} from '../dto/auth-response.dto';
import {UnitOfWorkPort} from '../uow/uow.port';

@Injectable()
export class ChangePasswordHandler {
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
    return await this.uow.withTransaction(async tx => {
      const existingUser = await this.userService.findUserByEmail(command.email || '');

      if (!existingUser || existingUser.id !== command.userId) {
        throw new UserNotFoundError();
      }

      if (!command.isForgetPassword) {
        await this.userService.verifyUserAndChangePassword(
          existingUser,
          {oldPassword: command.oldPassword, newPassword: command.newPassword},
          {user: {isForgetPassword: false}}
        );
      }

      const hashedPassword = await this.passwordService.hashPassword(command.newPassword, this.saltRounds);
      await tx.user.update({
        where: {id: command.userId},
        data: {password: hashedPassword, isForgetPassword: false}
      });

      return {
        success: true,
        message: AUTH_MESSAGES.PASSWORD_UPDATED
      };
    });
  }
}
