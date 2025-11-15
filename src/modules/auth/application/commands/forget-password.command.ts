import type {ForgetPasswordDto} from '../../interface/dto/auth-request.dto';

export class ForgetPasswordCommand {
  constructor(public readonly email: string) {}

  static fromDto(dto: ForgetPasswordDto): ForgetPasswordCommand {
    return new ForgetPasswordCommand(dto.email);
  }
}
