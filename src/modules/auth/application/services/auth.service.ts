import {Injectable} from '@nestjs/common';
import type {ChangePasswordDto, ForgetPasswordDto, ResendDto, SigninDto, SignupDto, VerificationDto} from '../../interface/dto/auth-request.dto';
import type {
  ChangePasswordSuccessResponseDto,
  ForgetPasswordSuccessResponseDto,
  RefreshTokenSuccessResponseDto,
  ResendSuccessResponseDto,
  SigninSuccessResponseDto,
  SignupSuccessResponseDto
} from '../../interface/dto/auth-response.dto';
import {ChangePasswordCommand} from '../commands/change-password.command';
import {ForgetPasswordCommand} from '../commands/forget-password.command';
import {OAuthSignInCommand} from '../commands/oauth-sign-in.command';
import {RefreshTokenCommand} from '../commands/refresh-token.command';
import {RegisterUserCommand} from '../commands/register-user.command';
import {ResendOtpCommand} from '../commands/resend-otp.command';
import {SignInCommand} from '../commands/sign-in.command';
import {VerifyOtpCommand} from '../commands/verify-otp.command';
import type {AuthenticatedRequest, OAuthUser} from '../types/auth.types';
import {ChangePasswordUseCase} from '../use-cases/change-password.use-case';
import {ForgetPasswordUseCase} from '../use-cases/forget-password.use-case';
import {OAuthSignInUseCase} from '../use-cases/oauth-sign-in.use-case';
import {RefreshTokenUseCase} from '../use-cases/refresh-token.use-case';
import {RegisterUserUseCase} from '../use-cases/register-user.use-case';
import {ResendOtpUseCase} from '../use-cases/resend-otp.use-case';
import {SignInUseCase} from '../use-cases/sign-in.use-case';
import {VerifyOtpUseCase} from '../use-cases/verify-otp.use-case';

@Injectable()
export class AuthService {
  constructor(
    private readonly registerUserUseCase: RegisterUserUseCase,
    private readonly signInUseCase: SignInUseCase,
    private readonly verifyOtpUseCase: VerifyOtpUseCase,
    private readonly resendOtpUseCase: ResendOtpUseCase,
    private readonly forgetPasswordUseCase: ForgetPasswordUseCase,
    private readonly changePasswordUseCase: ChangePasswordUseCase,
    private readonly refreshTokenUseCase: RefreshTokenUseCase,
    private readonly oAuthSignInUseCase: OAuthSignInUseCase
  ) {}

  async signup(signupData: SignupDto): Promise<SignupSuccessResponseDto> {
    const command = RegisterUserCommand.fromDto(signupData);
    return this.registerUserUseCase.execute(command);
  }

  async signin(signinData: SigninDto): Promise<SigninSuccessResponseDto> {
    const command = SignInCommand.fromDto(signinData);
    return this.signInUseCase.execute(command);
  }

  async verificationOtp(verificationData: VerificationDto): Promise<SigninSuccessResponseDto> {
    const command = VerifyOtpCommand.fromDto(verificationData);
    return this.verifyOtpUseCase.execute(command);
  }

  async resend(resendData: ResendDto): Promise<ResendSuccessResponseDto> {
    const command = ResendOtpCommand.fromDto(resendData);
    return this.resendOtpUseCase.execute(command);
  }

  async forgetPassword(forgetData: ForgetPasswordDto): Promise<ForgetPasswordSuccessResponseDto> {
    const command = ForgetPasswordCommand.fromDto(forgetData);
    return this.forgetPasswordUseCase.execute(command);
  }

  async changePassword(
    changePasswordData: ChangePasswordDto & {userId: number; email: string; isForgetPassword: boolean}
  ): Promise<ChangePasswordSuccessResponseDto> {
    const command = ChangePasswordCommand.fromDto(
      changePasswordData,
      changePasswordData.userId,
      changePasswordData.email,
      changePasswordData.isForgetPassword
    );
    return this.changePasswordUseCase.execute(command);
  }

  async refreshToken(req: AuthenticatedRequest): Promise<RefreshTokenSuccessResponseDto> {
    const command = RefreshTokenCommand.fromRequest(req.user);
    return this.refreshTokenUseCase.execute(command);
  }

  async oAuthSignin(oAuthUser: OAuthUser): Promise<SigninSuccessResponseDto> {
    const command = OAuthSignInCommand.fromUser(oAuthUser);
    return this.oAuthSignInUseCase.execute(command);
  }
}
