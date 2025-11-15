import type {SigninDto} from '../../interface/dto/auth-request.dto';

export class SignInCommand {
  constructor(
    public readonly email: string,
    public readonly password: string
  ) {}

  static fromDto(dto: SigninDto): SignInCommand {
    return new SignInCommand(dto.email, dto.password);
  }
}
