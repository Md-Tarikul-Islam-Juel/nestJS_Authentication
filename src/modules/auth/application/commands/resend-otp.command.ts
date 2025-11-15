import type {ResendDto} from '../../interface/dto/auth-request.dto';

export class ResendOtpCommand {
  constructor(public readonly email: string) {}

  static fromDto(dto: ResendDto): ResendOtpCommand {
    return new ResendOtpCommand(dto.email);
  }
}
