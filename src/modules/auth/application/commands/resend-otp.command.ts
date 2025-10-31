import {ResendDto} from '../dto/auth-request.dto';

export class ResendOtpCommand {
  constructor(public readonly email: string) {}

  static fromDto(dto: ResendDto): ResendOtpCommand {
    return new ResendOtpCommand(dto.email);
  }
}
