import type {ChangePasswordDto} from '../../interface/dto/auth-request.dto';

export class ChangePasswordCommand {
  constructor(
    public readonly userId: number,
    public readonly email: string,
    public readonly oldPassword?: string,
    public readonly newPassword: string = '',
    public readonly isForgetPassword: boolean = false
  ) {}

  static fromDto(dto: ChangePasswordDto, userId: number, email: string, isForgetPassword: boolean): ChangePasswordCommand {
    return new ChangePasswordCommand(userId, email, dto.oldPassword, dto.newPassword, isForgetPassword);
  }
}
