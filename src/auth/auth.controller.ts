import {
  Body,
  Controller,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { AuthGuard } from '@nestjs/passport';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { authDto } from './dto/index';
import { string } from './utils/index';

@Controller(string.AUTH)
export class AuthController {
  mailService: any;
  constructor(
    private readonly authService: AuthService,
    private jwt: JwtService,
  ) {}

  @HttpCode(HttpStatus.OK)
  @Post(string.SIGNUP)
  async signup(@Body() signupData: authDto.signupDtoType) {
    // Validate the request body using Joi DTO
    const validatedData = await authDto.signupDto.validateAsync(signupData);

    console.log('--------------------------------');
    console.log(validatedData);
    console.log('--------------------------------');
    // If validation passes, proceed with signup logic
    const result = await this.authService.signup(validatedData);

    return result;
  }

  @HttpCode(HttpStatus.OK)
  @Post(string.SIGNIN)
  async signin(@Body() signinData: authDto.signinDtoType) {
    // Validate the request body using Joi DTO
    const validatedData = await authDto.signinDto.validateAsync(signinData);

    // If validation passes, proceed with signin logic
    const result = await this.authService.signin(validatedData);

    return result;
  }

  @HttpCode(HttpStatus.OK)
  @Post(string.verification_otp)
  async verificationOtp(
    @Body() EmailVerificationByOTPData: authDto.verificationDtoType,
  ) {
    // Validate the request body using Joi DTO
    const validatedData = await authDto.verificationDto.validateAsync(
      EmailVerificationByOTPData,
    );

    // If validation passes, proceed with verification logic
    const result = await this.authService.verificationOtp(validatedData);

    return result;
  }

  @HttpCode(HttpStatus.OK)
  @Post(string.resend_otp)
  async resend(@Body() ResendOTPData: authDto.resendDtoType) {
    // Validate the request body using Joi DTO
    const validatedData = await authDto.resendDto.validateAsync(ResendOTPData);

    // If validation passes, proceed with resend logic
    const result = await this.authService.resend(validatedData);

    return result;
  }

  @HttpCode(HttpStatus.OK)
  @Post(string.forget_password_otp_send)
  async forgetPassword(
    @Body()
    ForgetPasswordSendEmailForOTPData: authDto.forgetPasswordDtoType,
  ) {
    // Validate the request body using Joi DTO
    const validatedData = await authDto.forgetPasswordDto.validateAsync(
      ForgetPasswordSendEmailForOTPData,
    );

    // If validation passes, proceed with forget password logic
    const result = await this.authService.forgetPassword(validatedData);

    return result;
  }

  @HttpCode(HttpStatus.OK)
  @UseGuards(AuthGuard('my_jwt_guard'))
  @Post(string.change_password)
  async ChangePassword(
    @Body() ChangePasswordData: authDto.changePasswordDtoType,
    @Req() req: Request,
  ) {
    // Validate the request body using Joi DTO
    const validatedData =
      await authDto.changePasswordDto.validateAsync(ChangePasswordData);

    // If validation passes, proceed with change password logic
    const result = await this.authService.ChangePassword(validatedData, req);

    return result;
  }

  @HttpCode(HttpStatus.OK)
  @Post('createUser')
  async createUser(@Body() body: any) {
    console.log(body);
    return await this.authService.createUser(body);
  }
}
