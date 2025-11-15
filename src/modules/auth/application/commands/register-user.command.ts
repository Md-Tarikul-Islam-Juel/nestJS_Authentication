import type {SignupDto} from '../../interface/dto/auth-request.dto';

export class RegisterUserCommand {
  constructor(
    public readonly email: string,
    public readonly password: string,
    public readonly firstName?: string,
    public readonly lastName?: string,
    public readonly mfaEnabled?: boolean
  ) {}

  static fromDto(dto: SignupDto): RegisterUserCommand {
    return new RegisterUserCommand(dto.email, dto.password, dto.firstName, dto.lastName, dto.mfaEnabled);
  }
}
