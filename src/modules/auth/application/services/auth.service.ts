import {Injectable} from '@nestjs/common';
import {ChangePasswordCommand} from '../commands/change-password.command';
import {ForgetPasswordCommand} from '../commands/forget-password.command';
import {OAuthSignInCommand} from '../commands/oauth-sign-in.command';
import {RefreshTokenCommand} from '../commands/refresh-token.command';
import {RegisterUserCommand} from '../commands/register-user.command';
import {ResendOtpCommand} from '../commands/resend-otp.command';
import {SignInCommand} from '../commands/sign-in.command';
import {VerifyOtpCommand} from '../commands/verify-otp.command';
import {ChangePasswordDto, ForgetPasswordDto, ResendDto, SigninDto, SignupDto, VerificationDto} from '../dto/auth-request.dto';
import {
  ChangePasswordSuccessResponseDto,
  ForgetPasswordSuccessResponseDto,
  RefreshTokenSuccessResponseDto,
  ResendSuccessResponseDto,
  SigninSuccessResponseDto,
  SignupSuccessResponseDto
} from '../dto/auth-response.dto';
import {ChangePasswordHandler} from '../handlers/change-password.handler';
import {ForgetPasswordHandler} from '../handlers/forget-password.handler';
import {OAuthSignInHandler} from '../handlers/oauth-sign-in.handler';
import {RefreshTokenHandler} from '../handlers/refresh-token.handler';
import {RegisterUserHandler} from '../handlers/register-user.handler';
import {ResendOtpHandler} from '../handlers/resend-otp.handler';
import {SignInHandler} from '../handlers/sign-in.handler';
import {VerifyOtpHandler} from '../handlers/verify-otp.handler';

@Injectable()
export class AuthService {
  constructor(
    private readonly registerUserHandler: RegisterUserHandler,
    private readonly signInHandler: SignInHandler,
    private readonly verifyOtpHandler: VerifyOtpHandler,
    private readonly resendOtpHandler: ResendOtpHandler,
    private readonly forgetPasswordHandler: ForgetPasswordHandler,
    private readonly changePasswordHandler: ChangePasswordHandler,
    private readonly refreshTokenHandler: RefreshTokenHandler,
    private readonly oAuthSignInHandler: OAuthSignInHandler
  ) {}

  async signup(signupData: SignupDto): Promise<SignupSuccessResponseDto> {
    const command = RegisterUserCommand.fromDto(signupData);
    return this.registerUserHandler.execute(command);
  }

  async signin(signinData: SigninDto): Promise<SigninSuccessResponseDto> {
    const command = SignInCommand.fromDto(signinData);
    return this.signInHandler.execute(command);
  }

  async verificationOtp(verificationData: VerificationDto): Promise<SigninSuccessResponseDto> {
    const command = VerifyOtpCommand.fromDto(verificationData);
    return this.verifyOtpHandler.execute(command);
  }

  async resend(resendData: ResendDto): Promise<ResendSuccessResponseDto> {
    const command = ResendOtpCommand.fromDto(resendData);
    return this.resendOtpHandler.execute(command);
  }

  async forgetPassword(forgetData: ForgetPasswordDto): Promise<ForgetPasswordSuccessResponseDto> {
    const command = ForgetPasswordCommand.fromDto(forgetData);
    return this.forgetPasswordHandler.execute(command);
  }

  async changePassword(changePasswordData: ChangePasswordDto, req: any): Promise<ChangePasswordSuccessResponseDto> {
    const command = ChangePasswordCommand.fromDto(changePasswordData, req.user.id, req.user.email, req.user.isForgetPassword || false);
    return this.changePasswordHandler.execute(command);
  }

  async refreshToken(req: any): Promise<RefreshTokenSuccessResponseDto> {
    const command = RefreshTokenCommand.fromRequest(req.user);
    return this.refreshTokenHandler.execute(command);
  }

  async oAuthSignin(oAuthUser: any): Promise<SigninSuccessResponseDto> {
    const command = OAuthSignInCommand.fromUser(oAuthUser);
    return this.oAuthSignInHandler.execute(command);
  }
}
