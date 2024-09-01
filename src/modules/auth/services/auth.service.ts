import {
  BadRequestException,
  ConflictException,
  HttpException,
  HttpStatus,
  Injectable,
  NotFoundException,
} from '@nestjs/common';

import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';

import {
  ChangePasswordDto,
  ForgetPasswordDto,
  OAuthDto,
  ResendDto,
  SigninDto,
  SignupDto,
  VerificationDto,
} from '../dtos/authRequest.dto';
import {
  ChangePasswordErrorResponseDto,
  ChangePasswordSuccessResponseDto,
  ForgetPasswordErrorResponseDto,
  ForgetPasswordSuccessResponseDto,
  RefreshTokenSuccessResponseDto,
  ResendErrorResponseDto,
  ResendSuccessResponseDto, SignInResponseUserDto,
  SigninSuccessResponseDto,
  SigninUnauthorizedResponseDto,
  SigninUserUnverifiedResponseDto, SignupResponseUserDto,
  SignupSuccessResponseDto,
  SignupUserAlreadyExistResponseDto,
  VerificationErrorResponseDto,
} from '../dtos/authRespnse.dto';
import {
  otpAuthorised,
  otpEmailSend,
  otpEmailSendFail,
  otpVerificationFailed,
  signinSuccessful,
  signupSuccessful, sucessfullyGenerateNewTokens,
  userAlreadyExists,
  userNotFound,
  verifyYourUser,
  yourPasswordHasBeenUpdated,
} from '../utils/string';
import { LoggerService } from '../../logger/logger.service';
import { PrismaService } from '../../prisma/prisma.service';

import { Tokens } from '../dtos/auth.base.dto';
import { UserService } from './user.service';
import { OtpService } from './otp.service';
import { TokenService } from './token.service';
import { EmailService } from './email.service';
import { CommonAuthService } from './commonAuth.service';
import { PasswordService } from './password.service';
import {
  ExistingUserInterface,
  CreatedUserInterface,
  TokenPayloadInterface,
  TokenConfig,
} from '../interfaces/auth.interface';

@Injectable()
export class AuthService {
  public otpExpireTime: number;
  private saltRounds: number;
  private tokenConfig: TokenConfig;

  constructor(
    private readonly prisma: PrismaService,
    private configService: ConfigService,
    private logger: LoggerService,
    private userService: UserService,
    private otpService: OtpService,
    private tokenService: TokenService,
    private emailService: EmailService,
    private readonly passwordService: PasswordService,
    private readonly commonAuthService: CommonAuthService,
  ) {
    this.saltRounds = this.configService.get<number>('authConfig.bcryptSaltRounds');
    this.otpExpireTime = this.configService.get<number>('authConfig.otpExpireTime');

    this.tokenConfig = {
      jweAccessTokenSecretKey: this.configService.get<string>('authConfig.jweAccessTokenSecretKey'),
      jwtAccessTokenSecretKey: this.configService.get<string>('authConfig.jwtAccessTokenSecretKey'),
      jweJwtAccessTokenExpireTime: this.configService.get<string>('authConfig.jweJwtAccessTokenExpireTime'),
      jweRefreshTokenSecretKey: this.configService.get<string>('authConfig.jweRefreshTokenSecretKey'),
      jwtRefreshTokenSecretKey: this.configService.get<string>('authConfig.jwtRefreshTokenSecretKey'),
      jweJwtRefreshTokenExpireTime: this.configService.get<string>('authConfig.jweJwtRefreshTokenExpireTime'),
    };
  }


  async signup(signupData: SignupDto): Promise<SignupSuccessResponseDto | SignupUserAlreadyExistResponseDto> {
    const existingUser: ExistingUserInterface = await this.userService.findUserByEmail(signupData.email);

    if (existingUser && existingUser.verified === true) {
      this.logger.error({
        message: userAlreadyExists,
        details: signupData,
      });

      throw new ConflictException({ message: userAlreadyExists });
    }

    const hashedPassword: string = await bcrypt.hash(signupData.password, this.saltRounds);
    const CreatedUserInterface: CreatedUserInterface = await this.userService.createUser(signupData, hashedPassword, 'default', false);//parameter(signupData, hashedPassword, loginSource, verified)

    await this.sendOtp(CreatedUserInterface.email);

    // Remove sensitive fields from the user data
    const sanitizedUserDataForResponse: SignupResponseUserDto = this.commonAuthService.removeSensitiveData(CreatedUserInterface, ['password', 'verified', 'isForgetPassword']);
    return {
      success: true,
      message: `${signupSuccessful} and please ${verifyYourUser}`,
      data: { user: sanitizedUserDataForResponse },
    };
  }

  async signin(signinData: SigninDto): Promise<SigninSuccessResponseDto | SigninUnauthorizedResponseDto | SigninUserUnverifiedResponseDto> {
    const existingUser: ExistingUserInterface = await this.userService.findUserByEmail(signinData.email);
    this.userService.authenticateUser(existingUser, signinData.password);

    await this.userService.updateForgotPasswordStatus(existingUser.email, false);
    // Remove sensitive fields from the user data
    const sanitizedUserDataForToken: TokenPayloadInterface = this.commonAuthService.removeSensitiveData(existingUser, ['password']);
    const sanitizedUserDataForResponse: SignInResponseUserDto = this.commonAuthService.removeSensitiveData(existingUser, ['password', 'verified', 'isForgetPassword']);

    const token: Tokens = await this.tokenService.generateTokens(sanitizedUserDataForToken, this.tokenConfig);

    return this.buildSigninResponse(sanitizedUserDataForResponse, token, signinSuccessful);
  }

  async oAuthSignin(oAuthSigninData: OAuthDto): Promise<SigninSuccessResponseDto> {
    let existingUser: ExistingUserInterface = await this.userService.findUserByEmail(oAuthSigninData.email);
    if (!existingUser) {
      const hashedPassword: string = await bcrypt.hash(this.passwordService.randomPasswordGenerator(10), this.saltRounds);
      existingUser = await this.userService.createUser(oAuthSigninData, hashedPassword, oAuthSigninData.loginSource, true);//parameter(signupData, hashedPassword, loginSource, verified)
    }

    // Remove sensitive fields from the user data
    const sanitizedUserDataForToken: TokenPayloadInterface = this.commonAuthService.removeSensitiveData(existingUser, ['password']);
    const sanitizedUserDataForResponse: SignInResponseUserDto = this.commonAuthService.removeSensitiveData(existingUser, ['password', 'verified', 'isForgetPassword']);

    const token: Tokens = await this.tokenService.generateTokens(sanitizedUserDataForToken, this.tokenConfig);
    return this.buildSigninResponse(sanitizedUserDataForResponse, token, signinSuccessful);
  }

  async verificationOtp(verificationData: VerificationDto): Promise<SigninSuccessResponseDto | VerificationErrorResponseDto> {
    const existingUser: ExistingUserInterface = await this.userService.findUserByEmail(verificationData.email);
    await this.verifyUserAndOtp(existingUser, verificationData.otp);
    await this.userService.updateUserVerificationStatus(existingUser.email, true);
    await this.otpService.deleteOtp(verificationData.email);
    const sanitizedUserDataForToken: TokenPayloadInterface = this.commonAuthService.removeSensitiveData(existingUser, ['password']);
    const token: Tokens = await this.tokenService.generateTokens(sanitizedUserDataForToken, this.tokenConfig);
    const sanitizedUserDataForResponse: SignInResponseUserDto = this.commonAuthService.removeSensitiveData(existingUser, ['password', 'verified', 'isForgetPassword']);
    return this.buildSigninResponse(sanitizedUserDataForResponse, token, otpAuthorised);
  }

  async resend(ResendOTPData: ResendDto): Promise<ResendSuccessResponseDto | ResendErrorResponseDto> {
    return this.sendOtp(ResendOTPData.email);
  }

  async forgetPassword(forgetData: ForgetPasswordDto): Promise<ForgetPasswordSuccessResponseDto | ForgetPasswordErrorResponseDto> {
    const existingUser: ExistingUserInterface = await this.userService.findUserByEmail(forgetData.email);

    //if verification fail then it will call callback function other wise not
    this.userService.verifyUserExist(existingUser, () => {
      //Error log already handle in verifyUserExist()
      throw new BadRequestException({ message: otpEmailSendFail });
    }, otpEmailSendFail);
    await this.userService.updateForgotPasswordStatus(existingUser.email, true);
    return this.sendOtp(existingUser.email);
  }

  async changePassword(changePasswordData: ChangePasswordDto, req: any): Promise<ChangePasswordErrorResponseDto | ChangePasswordSuccessResponseDto> {
    const existingUser: ExistingUserInterface = await this.userService.findUserByEmail(req.user.email);
    await this.userService.verifyUserAndChangePassword(existingUser, changePasswordData, req);
    await this.updatePassword(existingUser, changePasswordData.newPassword);
    return {
      success: true,
      message: yourPasswordHasBeenUpdated,
    };
  }

  async refreshToken(req: any): Promise<RefreshTokenSuccessResponseDto> {
    const existingUser: ExistingUserInterface = await this.userService.findUserByEmail(req.user.email);

    //if verification fail then it will call callback function other wist not
    this.userService.verifyUserExist(existingUser, () => {
      //Error log already handle in verifyUserExist()
      throw new HttpException(userNotFound, HttpStatus.NOT_FOUND);
    }, userNotFound);

    // Remove sensitive fields from the user data
    const sanitizedUserDataForToken: TokenPayloadInterface = this.commonAuthService.removeSensitiveData(existingUser, ['password']);

    const tokens: Tokens = await this.tokenService.generateTokens(sanitizedUserDataForToken, this.tokenConfig);
    return { success: true, message: sucessfullyGenerateNewTokens, tokens: tokens };
  }

  //----------------------------------------------------------------------------------------------------------------
  //----------------------------------------------------------------------------------------------------------------
  //----------------------------------------------------------------------------------------------------------------

  //OTP generate and email send
  public async sendOtp(email: string): Promise<ResendSuccessResponseDto | ResendErrorResponseDto> {
    // Find the user by email in the database
    // if user not found then no need to send email
    const existingUser: ExistingUserInterface = await this.userService.findUserByEmail(email);

    // If the user is not found, throw a NotFound exception
    if (!existingUser) {
      this.logger.error({
        message: `${otpEmailSendFail} because user not exist`,
        details: email,
      });
      throw new BadRequestException({ message: otpEmailSendFail });
    }

    const otp: string = this.otpService.generateOtp(6);// Generate a 6-digit OTP
    await this.otpService.storeOtp(email, otp, this.otpExpireTime);// Store the generated OTP in the database
    await this.emailService.sendOtpEmail(email, otp, this.otpExpireTime);// Send the OTP to the user's email

    return {
      success: true,
      message: otpEmailSend,
    };
  }

  public async verifyUserAndOtp(user: ExistingUserInterface, otp: string) {
    //if verification fail then it will call callback function other wist not
    this.userService.verifyUserExist(user, () => {
      //Error log already handle in verifyUserExist()
      throw new NotFoundException(otpVerificationFailed);
    }, otpVerificationFailed);

    await this.otpService.verifyOtp(user.email, otp);
  }

  public buildSigninResponse(user: SignInResponseUserDto, token: Tokens, message: string): SigninSuccessResponseDto {
    return {
      success: true,
      message: message,
      tokens: {
        accessToken: token.accessToken,
        refreshToken: token.refreshToken,
      },
      data: { user: user },
    };
  }

  public async updatePassword(user: ExistingUserInterface, newPassword: string): Promise<void> {
    const hashedPassword = await this.passwordService.hashPassword(newPassword, this.saltRounds);
    this.prisma.user.update({
      where: { id: user.id },
      data: { password: hashedPassword, isForgetPassword: false },
    });
  }
}
