import { MailerService } from '@nestjs-modules/mailer';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';

import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';
import * as otpGenerator from 'otp-generator';


import {
  ChangePasswordDto,
  ForgetPasswordDto,
  OAuthDto,
  ResendDto,
  SigninDto,
  SignupDto,
  VerificationDto,
} from '../dto/authRequest.dto';
import {
  ChangePasswordErrorResponseDto,
  ChangePasswordSuccessResponseDto,
  ForgetPasswordErrorResponseDto,
  ForgetPasswordSuccessResponseDto,
  RefreshTokenSuccessResponseDto,
  ResendErrorResponseDto,
  ResendSuccessResponseDto,
  SigninSuccessResponseDto,
  SigninUnauthorizedResponseDto,
  SigninUserUnverifiedResponseDto,
  SignupSuccessResponseDto,
  SignupUserAlreadyExistResponseDto,
  VerificationErrorResponseDto,
} from '../dto/authRespnse.dto';
import {
  emailSubject,
  failedToChangePassword,
  failedToSendOTPEmail,
  invalidOrExpiredOTP,
  oldPasswordIsRequired,
  otpAuthorised,
  otpEmailSend,
  otpEmailSendFail,
  otpVerificationFailed,
  signinSuccessful,
  signupSuccessful, sucessfullyGenerateNewTokens,
  unauthorized,
  userAlreadyExists,
  userNotFound,
  verifyYourUser,
  yourPasswordHasBeenUpdated,
} from '../utils/string';
import { LoggerService } from '../../logger/logger.service';
import { PrismaService } from '../../prisma/prisma.service';
import { CompactEncrypt } from 'jose';

import {
  CreatedUserDto,
  ExistingUserDto,
  SignInResponseUserDto,
  SignupResponseUserDto,
  TokenPayloadDto,
} from '../dto/auth.internal.dto';
import { Tokens } from '../dto/auth.base.dto';

@Injectable()
export class AuthService {
  private saltRounds: number;
  public otpExpireTime: number;
  private otpSenderMail: string;
  private jwtAccessTokenSecrectKey: string;
  private jwtRefreshTokenSecrectKey: string;
  private jweAccessTokenSecrectKey: string;
  private jweRefreshTokenSecrectKey: string;

  private jwejwtAccessTokenExpireTime: string;
  private jwejwtRefreshTokenExpireTime: string;


  constructor(
    private readonly prisma: PrismaService,
    private jwtAccessToken: JwtService,
    private jwtRefreshToken: JwtService,
    private config: ConfigService,
    private mailerService: MailerService,
    private logger: LoggerService,
  ) {
    this.saltRounds = Number(this.config.get<string>('BCRYPT_SALT_ROUNDS'));
    this.otpExpireTime = Number(this.config.get<string>('OTP_EXPIRE_TIME'));
    this.otpSenderMail = this.config.get<string>('OTP_SENDER_MAIL');

    this.jwtAccessTokenSecrectKey = this.config.get<string>('JWT_ACCESS_TOKEN_SECRET');
    this.jwtRefreshTokenSecrectKey = this.config.get<string>('JWT_REFRESH_TOKEN_SECRET');
    this.jweAccessTokenSecrectKey = this.config.get<string>('JWE_ACCESS_TOKEN_SECRET');
    this.jweRefreshTokenSecrectKey = this.config.get<string>('JWE_REFRESH_TOKEN_SECRET');

    this.jwejwtAccessTokenExpireTime = this.config.get<string>('JWE_JWT_ACCESS_TOKEN_EXPIRATION');
    this.jwejwtRefreshTokenExpireTime = this.config.get<string>('JWE_JWT_REFRESH_TOKEN_EXPIRATION');

  }


  async signup(signupData: SignupDto): Promise<SignupSuccessResponseDto | SignupUserAlreadyExistResponseDto> {
    const existingUser: ExistingUserDto = await this.findUserByEmail(signupData.email);

    if (existingUser && existingUser.verified === true) {
      this.logger.error({
        message: userAlreadyExists,
        details: signupData,
      });

      throw new ConflictException({ message: userAlreadyExists });
    }

    const hashedPassword: string = await bcrypt.hash(signupData.password, this.saltRounds);
    const CreatedUserDto: CreatedUserDto = await this.createUser(signupData, hashedPassword, 'default', false);//parameter(signupData, hashedPassword, loginSource, verified)

    await this.sendOtp(CreatedUserDto.email);

    // Remove sensitive fields from the user data
    const sanitizedUserDataForResponse: SignupResponseUserDto = this.removeSensitiveData(CreatedUserDto, ['password', 'verified', 'isForgetPassword']);
    return {
      success: true,
      message: `${signupSuccessful} and please ${verifyYourUser}`,
      data: { user: sanitizedUserDataForResponse },
    };
  }

  async signin(signinData: SigninDto): Promise<SigninSuccessResponseDto | SigninUnauthorizedResponseDto | SigninUserUnverifiedResponseDto> {
    const existingUser: ExistingUserDto = await this.findUserByEmail(signinData.email);
    this.authenticateUser(existingUser, signinData.password);

    await this.updateForgotPasswordStatus(existingUser.email, false);
    // Remove sensitive fields from the user data
    const sanitizedUserDataForToken: TokenPayloadDto = this.removeSensitiveData(existingUser, ['password']);
    const sanitizedUserDataForResponse: SignInResponseUserDto = this.removeSensitiveData(existingUser, ['password', 'verified', 'isForgetPassword']);

    const token: Tokens = await this.generateTokens(sanitizedUserDataForToken);

    return this.buildSigninResponse(sanitizedUserDataForResponse, token, signinSuccessful);
  }

  async oAuthSignin(oAuthSigninData: OAuthDto): Promise<SigninSuccessResponseDto> {
    let existingUser: ExistingUserDto = await this.findUserByEmail(oAuthSigninData.email);
    if (!existingUser) {
      const hashedPassword: string = await bcrypt.hash(this.randomPasswordGenerator(10), this.saltRounds);
      existingUser = await this.createUser(oAuthSigninData, hashedPassword, oAuthSigninData.loginSource, true);//parameter(signupData, hashedPassword, loginSource, verified)
    }

    // Remove sensitive fields from the user data
    const sanitizedUserDataForToken: TokenPayloadDto = this.removeSensitiveData(existingUser, ['password']);
    const sanitizedUserDataForResponse: SignInResponseUserDto = this.removeSensitiveData(existingUser, ['password', 'verified', 'isForgetPassword']);

    const token: Tokens = await this.generateTokens(sanitizedUserDataForToken);
    return this.buildSigninResponse(sanitizedUserDataForResponse, token, signinSuccessful);
  }

  async verificationOtp(verificationData: VerificationDto): Promise<SigninSuccessResponseDto | VerificationErrorResponseDto> {
    const existingUser: ExistingUserDto = await this.findUserByEmail(verificationData.email);
    await this.verifyUserAndOtp(existingUser, verificationData.otp);
    await this.updateUserVerificationStatus(existingUser.email, true);
    await this.deleteOtp(verificationData.email);
    const sanitizedUserDataForToken: TokenPayloadDto = this.removeSensitiveData(existingUser, ['password']);
    const token: Tokens = await this.generateTokens(sanitizedUserDataForToken);
    const sanitizedUserDataForResponse: SignInResponseUserDto = this.removeSensitiveData(existingUser, ['password', 'verified', 'isForgetPassword']);
    return this.buildSigninResponse(sanitizedUserDataForResponse, token, otpAuthorised);
  }

  async resend(ResendOTPData: ResendDto): Promise<ResendSuccessResponseDto | ResendErrorResponseDto> {
    return this.sendOtp(ResendOTPData.email);
  }

  async forgetPassword(forgetData: ForgetPasswordDto): Promise<ForgetPasswordSuccessResponseDto | ForgetPasswordErrorResponseDto> {
    const existingUser: ExistingUserDto = await this.findUserByEmail(forgetData.email);

    //if verification fail then it will call callback function other wise not
    this.verifyUserExist(existingUser, () => {
      //Error log already handle in verifyUserExist()
      throw new BadRequestException({ message: otpEmailSendFail });
    }, otpEmailSendFail);
    await this.updateForgotPasswordStatus(existingUser.email, true);
    return this.sendOtp(existingUser.email);
  }

  async changePassword(changePasswordData: ChangePasswordDto, req: any): Promise<ChangePasswordErrorResponseDto | ChangePasswordSuccessResponseDto> {
    const existingUser: ExistingUserDto = await this.findUserByEmail(req.user.email);
    await this.verifyUserAndChangePassword(existingUser, changePasswordData, req);
    await this.updatePassword(existingUser, changePasswordData.newPassword);
    return {
      success: true,
      message: yourPasswordHasBeenUpdated,
    };
  }

  async refreshToken(req: any): Promise<RefreshTokenSuccessResponseDto> {
    const existingUser: ExistingUserDto = await this.findUserByEmail(req.user.email);

    //if verification fail then it will call callback function other wist not
    this.verifyUserExist(existingUser, () => {
      //Error log already handle in verifyUserExist()
      throw new HttpException(userNotFound, HttpStatus.NOT_FOUND);
    }, userNotFound);

    // Remove sensitive fields from the user data
    const sanitizedUserDataForToken: TokenPayloadDto = this.removeSensitiveData(existingUser, ['password']);

    const tokens: Tokens = await this.generateTokens(sanitizedUserDataForToken);
    return { success: true, message: sucessfullyGenerateNewTokens, tokens: tokens };
  }

  //-----------------------------------------------------------------------------
  //-------------------------------reuse method----------------------------------
  //-----------------------------------------------------------------------------
  //OTP generate and email send
  public async sendOtp(email: string): Promise<ResendSuccessResponseDto | ResendErrorResponseDto> {
    // Find the user by email in the database
    // if user not found then no need to send email
    const existingUser: ExistingUserDto = await this.findUserByEmail(email);

    // If the user is not found, throw a NotFound exception
    if (!existingUser) {
      this.logger.error({
        message: `${otpEmailSendFail} because user not exist`,
        details: email,
      });
      throw new BadRequestException({ message: otpEmailSendFail });
    }

    const otp: string = this.generateOtp(6);// Generate a 6-digit OTP
    await this.storeOtp(email, otp);// Store the generated OTP in the database
    await this.sendOtpEmail(email, otp, this.otpExpireTime);// Send the OTP to the user's email

    return {
      success: true,
      message: otpEmailSend,
    };
  }

  public async findUserByEmail(email: string): Promise<ExistingUserDto> {
    return this.prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        password: true,
        verified: true,
        isForgetPassword: true,
      },
    });
  }

  public async createUser(userData: SignupDto | OAuthDto, password: string, loginSource: string, verified: boolean): Promise<ExistingUserDto> {
    return this.prisma.user.upsert({
      where: { email: userData.email },
      update: {
        ...userData,
        loginSource: loginSource,
        verified: verified,
        isForgetPassword: false,
        password: password,
      },
      create: {
        ...userData,
        loginSource: loginSource,
        verified: verified,
        isForgetPassword: false,
        password: password,
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        verified: true,
        password: true,
        isForgetPassword: true,
      },
    });
  }

  public authenticateUser(user: ExistingUserDto, password: string): void {
    // Note: here bcrypt.compareSync(password, user.password) slow down the login process
    if (!user) {
      this.logger.error({
        message: `${unauthorized} because user not exist`,
        details: this.removeSensitiveData(user, ['password']),
      });
      throw new UnauthorizedException({ message: unauthorized });
    } else if (!bcrypt.compareSync(password, user.password)) {
      this.logger.error({
        message: `${unauthorized} because user password not matched`,
        details: this.removeSensitiveData(user, ['password']),
      });
      throw new UnauthorizedException({ message: unauthorized });
    } else if (!user.verified) {
      this.logger.error({
        message: `${verifyYourUser}`,
        details: this.removeSensitiveData(user, ['password']),
      });
      throw new ForbiddenException({ message: verifyYourUser });
    }
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

  public async verifyUserAndOtp(user: ExistingUserDto, otp: string) {
    //if verification fail then it will call callback function other wist not
    this.verifyUserExist(user, () => {
      //Error log already handle in verifyUserExist()
      throw new NotFoundException(otpVerificationFailed);
    }, otpVerificationFailed);

    await this.verifyOtp(user.email, otp);
  }

  public verifyUserExist(user: ExistingUserDto, callback: () => void, message: string): void {
    if (!user) {
      this.logger.error({
        message: `${message}`,
        details: this.removeSensitiveData(user, ['password']),
      });
      callback();
    }
  }

  public async deleteOtp(email: string) {
    return this.prisma.OTP.delete({ where: { email } });
  }

  public async updateForgotPasswordStatus(email: string, boolValue: boolean): Promise<void> {
    this.prisma.user.update({
      where: { email },
      data: { isForgetPassword: boolValue },
    });
  }

  public async updateUserVerificationStatus(email: string, verified: boolean): Promise<void> {
    await this.prisma.user.update({
      where: {
        email,
      },
      data: {
        verified,
      },
    });
  }

  public async verifyUserAndChangePassword(existingUser: ExistingUserDto, changePasswordData: ChangePasswordDto, req: any) {
    if (!existingUser) {
      this.logger.error({
        message: `${failedToChangePassword} because user not exist`,
        details: this.removeSensitiveData(existingUser, ['password']),
      });
      throw new BadRequestException({ message: failedToChangePassword });
    } else if (req.user.isForgetPassword === true && existingUser.isForgetPassword === true && existingUser.verified === true) {
      // ================================
      // this block for Forget password
      // ================================
      return;
    } else if (req.user.isForgetPassword === false && existingUser.isForgetPassword === false && existingUser.verified === true) {
      // ================================
      // this block for change password
      // ================================

      if (!changePasswordData.oldPassword) {
        this.logger.error({
          message: `${oldPasswordIsRequired}`,
          details: this.removeSensitiveData(existingUser, ['password']),
        });
        throw new BadRequestException({ message: oldPasswordIsRequired });
      }

      // Compare the provided password with the hashed password
      const passwordMatch: boolean = await bcrypt.compare(
        changePasswordData.oldPassword,
        existingUser.password,
      );

      // If passwords don't match,
      if (!passwordMatch) {
        this.logger.error({
          message: `${failedToChangePassword} because password not matched`,
          details: this.removeSensitiveData(existingUser, ['password']),
        });
        throw new BadRequestException({ message: failedToChangePassword });
      } else if (passwordMatch) {
        return;
      }
    }

    this.logger.error({
      message: `${failedToChangePassword}`,
      details: this.removeSensitiveData(existingUser, ['password']),
    });
    throw new BadRequestException({ message: failedToChangePassword });
  }

  public async updatePassword(user: ExistingUserDto, newPassword: string): Promise<void> {
    const hashedPassword: string = await bcrypt.hash(newPassword, this.saltRounds);
    this.prisma.user.update({
      where: { id: user.id },
      data: { password: hashedPassword, isForgetPassword: false },
    });
  }

  public removeSensitiveData(obj: any, sensitiveFields: string[]) {
    const filteredObj = { ...obj };

    sensitiveFields.forEach(field => {
      delete filteredObj[field];
    });

    return filteredObj;
  }

  public generateOtp(length: number): string {
    return otpGenerator.generate(length, {
      digits: true,
      upperCase: false,
      lowercase: false,
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false,
    });
  }

  public async storeOtp(email: string, otp: string): Promise<void> {
    const expiryTime: Date = new Date(Date.now() + this.otpExpireTime * 60 * 1000); // 10 minutes expiry

    await this.prisma.OTP.upsert({
      where: { email },
      update: { otp, expiresAt: expiryTime },
      create: { email, otp, expiresAt: expiryTime },
    });
  }

  public async sendOtpEmail(email: string, otp: string, expireTime: number): Promise<void> {
    try {
      const mailOptions = {
        to: email,
        from: this.otpSenderMail,
        subject: emailSubject,
        text: `Your OTP code is: ${otp}. It is valid for ${expireTime} minutes.`,
      };

      await this.mailerService.sendMail(mailOptions);
    } catch (error) {
      this.logger.error({
        message: `${failedToSendOTPEmail}`,
        details: email,
      });
      console.error(failedToSendOTPEmail, error);
      throw new InternalServerErrorException(failedToSendOTPEmail);
    }
  }

  public async verifyOtp(email: string, otp: string): Promise<void> {
    const otpRecord = await this.prisma.OTP.findUnique({
      where: { email },
      select: { otp: true, expiresAt: true },
    });

    if (!otpRecord || otpRecord.otp !== otp || new Date() > otpRecord.expiresAt) {
      this.logger.error({
        message: `${invalidOrExpiredOTP}`,
        details: email,
      });
      throw new UnauthorizedException(invalidOrExpiredOTP);
    }
  }

  public async generateTokens(user: TokenPayloadDto): Promise<Tokens> {
    // Remove sensitive fields from the user data
    const sanitizedUserDataForToken: TokenPayloadDto = this.removeSensitiveData(user, ['password']);

    const accessToken: string = await this.generateJwtAccessToken(this.jwtAccessToken, sanitizedUserDataForToken);
    const refreshToken: string = await this.generateJwtRefreshToken(this.jwtRefreshToken, sanitizedUserDataForToken);

    return { accessToken, refreshToken };
  }

  public async generateJwtAccessToken(jwtService: JwtService, existingUser: TokenPayloadDto): Promise<string> {
    const sanitizedUserDataForToken: TokenPayloadDto = this.removeSensitiveData(existingUser, ['password', 'updatedAt', 'createdAt']);
    const jwtToken: string = jwtService.sign(sanitizedUserDataForToken, {
      expiresIn: this.jwejwtAccessTokenExpireTime,
      secret: this.jwtAccessTokenSecrectKey,
    });

    const jweSecretKey = new TextEncoder().encode(this.jweAccessTokenSecrectKey);

    return await new CompactEncrypt(new TextEncoder().encode(jwtToken))
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .encrypt(jweSecretKey);
  }

  public async generateJwtRefreshToken(jwtService: JwtService, existingUser: TokenPayloadDto): Promise<string> {
    const sanitizedUserDataForToken: TokenPayloadDto = this.removeSensitiveData(existingUser, ['password', 'updatedAt', 'createdAt']);
    const jwtToken: string = jwtService.sign(sanitizedUserDataForToken, {
      expiresIn: this.jwejwtRefreshTokenExpireTime,
      secret: this.jwtRefreshTokenSecrectKey,
    });

    const jweSecretKey = new TextEncoder().encode(this.jweRefreshTokenSecrectKey);

    return await new CompactEncrypt(new TextEncoder().encode(jwtToken))
      .setProtectedHeader({ alg: 'dir', enc: 'A256GCM' })
      .encrypt(jweSecretKey);
  }

  public randomPasswordGenerator(length: number): string {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let code: string = '';

    const randomNumber: number = Math.floor(Math.random() * 10);
    code += randomNumber.toString();

    for (let i: number = 1; i < length; i++) {
      const randomIndex: number = Math.floor(Math.random() * charset.length);
      code += charset[randomIndex];
    }

    return code;
  }
}
