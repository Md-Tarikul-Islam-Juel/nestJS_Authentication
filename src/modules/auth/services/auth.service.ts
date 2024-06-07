import { MailerService } from '@nestjs-modules/mailer';
import {
  BadRequestException,
  ConflictException, ForbiddenException, HttpException, HttpStatus,
  Injectable, InternalServerErrorException, NotFoundException, UnauthorizedException,
} from '@nestjs/common';

import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

import * as otpGenerator from 'otp-generator';
import { PrismaService } from 'src/modules/prisma/prisma.service';

import {
  ChangePasswordDto,
  ForgetPasswordDto, OAuthDto,
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
  VerificationSuccessResponseDto,
} from '../dto/authRespnse.dto';
import {
  emailSubject,
  failedToChangePassword, oldPasswordIsRequired,
  otpAuthorised, otpEmailSend, otpEmailSendFail,
  otpVerificationFailed,
  signinSuccessful,
  signupSuccessful,
  unauthorized,
  userAlreadyExists,
  verifyYourUser, yourPasswordHasBeenUpdated,
} from '../utils/string';


@Injectable()
export class AuthService {
  private saltRounds: number;
  private otpExpireTime: number;
  private otpSenderMail: string;
  private jwtAccessTokenSecrectKey: string;
  private jwtRefreshTokenSecrectKey: string;
  private jwtAccessTokenExpireTime: string;
  private jwtRefreshTokenExpireTime: string;

  constructor(
    private readonly prisma: PrismaService,
    private jwtAccessToken: JwtService,
    private jwtRefreshToken: JwtService,
    private config: ConfigService,
    private mailerService: MailerService,
  ) {
    this.saltRounds = Number(this.config.get<string>('BCRYPT_SALT_ROUNDS'));
    this.otpExpireTime = Number(this.config.get<string>('OTP_EXPIRE_TIME'));
    this.otpSenderMail = this.config.get<string>('OTP_SENDER_MAIL');
    this.jwtAccessTokenSecrectKey = this.config.get<string>('JWT_ACCESS_TOKEN_SECRET');
    this.jwtRefreshTokenSecrectKey = this.config.get<string>('JWT_REFRESH_TOKEN_SECRET');
    this.jwtAccessTokenExpireTime = this.config.get<string>('JWT_ACCESS_TOKEN_EXPIRATION');
    this.jwtRefreshTokenExpireTime = this.config.get<string>('JWT_REFRESH_TOKEN_EXPIRATION');
  }


  async signup(signupData: SignupDto): Promise<SignupSuccessResponseDto | SignupUserAlreadyExistResponseDto> {
    const isUserExist = await this.findUserByEmail(signupData.email);

    if (isUserExist) {
      throw new ConflictException({ message: userAlreadyExists });
    }

    const hashedPassword = await bcrypt.hash(signupData.password, this.saltRounds);
    const createdUser = await this.createUser(signupData, hashedPassword, 'default', false);//parameter(signupData, hashedPassword, loginSource, verified)

    await this.sendOtp(createdUser.email);

    // Remove sensitive fields from the user data
    const userWithoutSensitiveData = this.removeSensitiveData(createdUser, ['password', 'verified', 'isForgetPassword']);
    return {
      success: true,
      message: `${signupSuccessful} and please ${verifyYourUser}`,
      data: userWithoutSensitiveData,
    };
  }

  async signin(signinData: SigninDto): Promise<SigninSuccessResponseDto | SigninUnauthorizedResponseDto | SigninUserUnverifiedResponseDto> {
    const existingUser = await this.findUserByEmail(signinData.email);
    this.authenticateUser(existingUser, signinData.password);
    await this.updateForgetPasswordField(existingUser.email, false);

    // Remove sensitive fields from the user data
    const userWithoutSensitiveDataForToken = this.removeSensitiveData(existingUser, ['password']);
    const userWithoutSensitiveDataForResponse = this.removeSensitiveData(existingUser, ['password', 'verified', 'isForgetPassword']);

    const token = this.generateToken(userWithoutSensitiveDataForToken);
    return this.buildSigninResponse(userWithoutSensitiveDataForResponse, token);
  }

  async oAuthSignin(oAuthSigninData: OAuthDto): Promise<SigninSuccessResponseDto> {
    let existingUser = await this.findUserByEmail(oAuthSigninData.email);
    if (!existingUser) {
      const hashedPassword = await bcrypt.hash(this.randomPasswordGenerator(10), this.saltRounds);
      existingUser = await this.createUser(oAuthSigninData, hashedPassword, oAuthSigninData.loginSource, true);//parameter(signupData, hashedPassword, loginSource, verified)
    }

    // Remove sensitive fields from the user data
    const userWithoutSensitiveDataForToken = this.removeSensitiveData(existingUser, ['password']);
    const userWithoutSensitiveDataForResponse = this.removeSensitiveData(existingUser, ['password', 'verified', 'isForgetPassword']);

    const token = this.generateToken(userWithoutSensitiveDataForToken);
    return this.buildSigninResponse(userWithoutSensitiveDataForResponse, token);
  }

  async verificationOtp(verificationData: VerificationDto): Promise<VerificationSuccessResponseDto | VerificationErrorResponseDto> {
    const existingUser = await this.findUserByEmail(verificationData.email);
    await this.verifyUserAndOtp(existingUser, verificationData.otp);
    await this.updateUserVerificationStatus(existingUser.email, true);
    await this.deleteOtp(verificationData.email);
    const token = this.generateToken(existingUser);
    const userWithoutSensitiveData = this.removeSensitiveData(existingUser, ['password', 'verified', 'isForgetPassword']);
    return this.buildOtpResponse(userWithoutSensitiveData, token);
  }

  async resend(ResendOTPData: ResendDto): Promise<ResendSuccessResponseDto | ResendErrorResponseDto> {
    return this.sendOtp(ResendOTPData.email);
  }

  async forgetPassword(forgetData: ForgetPasswordDto): Promise<ForgetPasswordSuccessResponseDto | ForgetPasswordErrorResponseDto> {
    const existingUser = await this.findUserByEmail(forgetData.email);
    //if verification fail then it will call callback function other wist not
    this.verifyUserExist(existingUser, () => {
      throw new BadRequestException({ message: otpEmailSendFail });
    });
    await this.updateForgetPasswordField(existingUser.email, true);
    return this.sendOtp(existingUser.email);
  }

  async changePassword(changePasswordData: ChangePasswordDto, req: any): Promise<ChangePasswordErrorResponseDto | ChangePasswordSuccessResponseDto> {
    const existingUser = await this.findUserByEmail(req.user.email);
    await this.verifyUserAndChangePassword(existingUser, changePasswordData, req);
    await this.updatePassword(existingUser, changePasswordData.newPassword);
    return {
      success: true,
      message: yourPasswordHasBeenUpdated,
    };
  }

  async refreshToken(req: any): Promise<RefreshTokenSuccessResponseDto> {
    const existingUser = await this.findUserByEmail(req.user.email);

    //if verification fail then it will call callback function other wist not
    this.verifyUserExist(existingUser, () => {
      throw new HttpException('Invalid Refresh Token', HttpStatus.NOT_FOUND);
    });

    // Remove sensitive fields from the user data
    const userWithoutSensitiveDataForToken = this.removeSensitiveData(existingUser, ['password']);

    const token = this.generateToken(userWithoutSensitiveDataForToken);
    return { success: true, accessToken: token.accessToken };
  }

  //-----------------------------------------------------------------------------
  //-------------------------------reuse method----------------------------------
  //-----------------------------------------------------------------------------
  //OTP generate and email send
  private async sendOtp(email: string): Promise<ResendSuccessResponseDto | ResendErrorResponseDto> {
    // Find the user by email in the database
    // if user not found then no need to send email
    const existingUser = await this.findUserByEmail(email);

    // If the user is not found, throw a NotFound exception
    if (!existingUser) {
      throw new BadRequestException({ message: otpEmailSendFail });
    }

    const otp = this.generateOtp(6);
    await this.storeOtp(email, otp);
    await this.sendOtpEmail(email, otp, this.otpExpireTime);

    return {
      success: true,
      message: otpEmailSend,
    };
  }

  private async findUserByEmail(email: string): Promise<{
    id: number,
    email: string,
    password: string,
    firstName: string,
    lastName: string,
    verified: boolean,
    isForgetPassword: boolean,
  }> {
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

  private async createUser(userData: any, password: string, loginSource: string, verified: boolean): Promise<{
    id: number,
    email: string,
    password: string,
    firstName: string,
    lastName: string,
    verified: boolean,
    isForgetPassword: boolean,
  }> {
    return this.prisma.user.create({
      data: {
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

  private authenticateUser(user: any, password: string): void {
    if (!user) {
      throw new UnauthorizedException({ message: unauthorized });
    }
    if (!bcrypt.compareSync(password, user.password)) {
      throw new UnauthorizedException({ message: unauthorized });
    }
    if (!user.verified) {
      throw new ForbiddenException({ message: verifyYourUser });
    }
  }

  private buildSigninResponse(user: any, token: any): {
    success: boolean,
    message: string,
    accessToken: string,
    refreshToken: string,
    data: any
  } {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, verified, ...restUser } = user;
    return {
      success: true,
      message: signinSuccessful,
      accessToken: token.accessToken,
      refreshToken: token.refreshToken,
      data: restUser,
    };
  }

  private async verifyUserAndOtp(user: any, otp: string) {
    //if verification fail then it will call callback function other wist not
    this.verifyUserExist(user, () => {
      throw new NotFoundException(otpVerificationFailed);
    });

    await this.verifyOtp(user.email, otp);

    // const savedOtp = await this.prisma.OTP.findUnique({ where: { email: user.email }, select: { otp: true } });
    //
    // if (!savedOtp || savedOtp.otp !== otp) {
    //   throw new UnauthorizedException({ message: otpVerificationFailed });
    // }
  }

  private verifyUserExist(user: any, callback: () => void): void {
    if (!user) {
      callback();
    }
  }

  private async deleteOtp(email: string) {
    return this.prisma.OTP.delete({ where: { email } });
  }

  private buildOtpResponse(user: any, token: any): {
    success: boolean,
    message: string,
    accessToken: string,
    refreshToken: string,
    data: any
  } {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, ...restUser } = user;
    return {
      success: true,
      message: otpAuthorised,
      accessToken: token.accessToken,
      refreshToken: token.refreshToken,
      data: restUser,
    };
  }

  private async updateForgetPasswordField(email: string, boolValue: boolean): Promise<any> {
    return this.prisma.user.update({
      where: { email },
      data: { isForgetPassword: boolValue },
    });
  }

  private async updateUserVerificationStatus(email: string, verified: boolean): Promise<void> {
    await this.prisma.user.update({
      where: {
        email,
      },
      data: {
        verified,
      },
    });
  }

  private async verifyUserAndChangePassword(existingUser: any, changePasswordData: ChangePasswordDto, req: any) {
    if (!existingUser) {
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
        throw new BadRequestException({ message: oldPasswordIsRequired });
      }

      // Compare the provided password with the hashed password
      const passwordMatch = await bcrypt.compare(
        changePasswordData.oldPassword,
        existingUser.password,
      );

      // If passwords don't match,
      if (!passwordMatch) {
        throw new BadRequestException({ message: failedToChangePassword });
      } else if (passwordMatch) {
        return;
      }
    }

    throw new BadRequestException({ message: failedToChangePassword });
  }

  private async updatePassword(user: any, newPassword: string): Promise<{
    password: string;
    isForgetPassword: boolean
  }> {
    const hashedPassword = await bcrypt.hash(newPassword, this.saltRounds);
    return this.prisma.user.update({
      where: { id: user.id },
      data: { password: hashedPassword, isForgetPassword: false },
    });
  }

  private removeSensitiveData(obj: any, sensitiveFields: string[]): any {
    const filteredObj = { ...obj };

    sensitiveFields.forEach(field => {
      delete filteredObj[field];
    });

    return filteredObj;
  }

  private generateOtp(length: number): string {
    return otpGenerator.generate(length, {
      digits: true,
      upperCase: false,
      lowercase: false,
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false,
    });
  }

  private async storeOtp(email: string, otp: string): Promise<void> {
    const expiryTime = new Date(Date.now() + this.otpExpireTime * 60 * 1000); // 10 minutes expiry

    await this.prisma.OTP.upsert({
      where: { email },
      update: { otp, expiresAt: expiryTime },
      create: { email, otp, expiresAt: expiryTime },
    });
  }

  private async sendOtpEmail(email: string, otp: string, expireTime: number): Promise<void> {
    try {
      const mailOptions = {
        to: email,
        from: this.otpSenderMail,
        subject: emailSubject,
        text: `Your OTP code is: ${otp}. It is valid for ${expireTime} minutes.`,
      };

      await this.mailerService.sendMail(mailOptions);
    } catch (error) {
      console.error('Failed to send OTP email:', error);
      throw new InternalServerErrorException('Failed to send OTP email.');
    }
  }

  private async verifyOtp(email: string, otp: string): Promise<void> {
    const otpRecord = await this.prisma.OTP.findUnique({
      where: { email },
      select: { otp: true, expiresAt: true },
    });

    if (!otpRecord || otpRecord.otp !== otp || new Date() > otpRecord.expiresAt) {
      throw new UnauthorizedException('Invalid or expired OTP.');
    }
  }

  // Generate accessToken and refreshToken
  private generateToken(user: any): { accessToken: string; refreshToken: string } {
    // Remove sensitive fields from the user data
    const userWithoutSensitiveData = this.removeSensitiveData(user, ['password']);

    const accessToken = this.generateJwtAccessToken(this.jwtAccessToken, userWithoutSensitiveData);
    const refreshToken = this.generateJwtRefreshToken(this.jwtRefreshToken, userWithoutSensitiveData);

    return { accessToken, refreshToken };
  }

  private generateJwtAccessToken(jwtService: JwtService, existingUser: any): string {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, updatedAt, createdAt, ...restUser } = existingUser;
    const payload = { ...restUser };
    return jwtService.sign(payload, {
      expiresIn: this.jwtAccessTokenExpireTime,
      secret: this.jwtAccessTokenSecrectKey,
    });
  }

  private generateJwtRefreshToken(jwtService: JwtService, existingUser: any): string {
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password, updatedAt, createdAt, ...restUser } = existingUser;
    const payload = { ...restUser };
    return jwtService.sign(payload, {
      expiresIn: this.jwtRefreshTokenExpireTime,
      secret: this.jwtRefreshTokenSecrectKey,
    });
  }

  private randomPasswordGenerator(length: number): string {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let code = '';

    const randomNumber = Math.floor(Math.random() * 10);
    code += randomNumber.toString();

    for (let i = 1; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * charset.length);
      code += charset[randomIndex];
    }

    return code;
  }
}
