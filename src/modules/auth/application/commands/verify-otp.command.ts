import type {VerificationDto} from '../../interface/dto/auth-request.dto';

export class VerifyOtpCommand {
  constructor(
    public readonly email: string,
    public readonly otp: string
  ) {}

  static fromDto(dto: VerificationDto): VerifyOtpCommand {
    return new VerifyOtpCommand(dto.email, dto.otp);
  }
}
