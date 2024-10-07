import {Body, Controller, Get, HttpCode, HttpStatus, Inject, Post, Req, UseGuards, UseInterceptors} from '@nestjs/common';
import {AuthGuard} from '@nestjs/passport';
import {Request} from 'express';
import {AuthService} from '../services/auth.service';
import {ChangePasswordDto, ForgetPasswordDto, ResendDto, SigninDto, SignupDto, VerificationDto} from '../dtos/authRequest.dto';
import {ApiBody, ApiCreatedResponse, ApiOkResponse, ApiOperation, ApiResponse, ApiTags} from '@nestjs/swagger';

import {
  ChangePasswordErrorResponseDto,
  ChangePasswordSuccessResponseDto,
  ChangePasswordUnverifiedResponseDto,
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
  VerificationErrorResponseDto
} from '../dtos/authRespnse.dto';
import {
  AUTH,
  change_password,
  forget_password_otp_send,
  LOGOUT_ALL,
  REFRESH_TOKEN,
  resend_otp,
  SIGNIN,
  SIGNUP,
  verification_otp
} from '../utils/string';
import {JweJwtAccessTokenStrategy} from '../../token/strategy/jwe-jwt-access-token.strategy';
import {JweJwtRefreshTokenStrategy} from '../../token/strategy/jwe-jwt-refresh-token.strategy';
import {TrackLastActivityInterceptor} from '../Interceptor/trackLastActivityInterceptor.interceptor';
import {LogoutService} from '../services/logout.service';

@ApiTags('Auth')
@Controller(AUTH)
@UseInterceptors(TrackLastActivityInterceptor) // to track user last uses time based on token
export class AuthController {
  constructor(
    @Inject(AuthService)
    private readonly authService: AuthService,
    private readonly logoutService: LogoutService
  ) {}

  @HttpCode(HttpStatus.CREATED)
  @Post(SIGNUP)
  @ApiOperation({summary: 'Sign up user'})
  @ApiBody({type: SignupDto})
  @ApiCreatedResponse({description: 'Sign up success', type: SignupSuccessResponseDto})
  @ApiResponse({
    status: HttpStatus.CONFLICT,
    description: 'User already exist',
    type: SignupUserAlreadyExistResponseDto
  })
  async signup(@Body() signupData: SignupDto): Promise<SignupSuccessResponseDto | SignupUserAlreadyExistResponseDto> {
    return this.authService.signup(signupData);
  }

  @HttpCode(HttpStatus.OK)
  @Post(SIGNIN)
  @ApiOperation({summary: 'Sign in user'})
  @ApiBody({type: SigninDto})
  @ApiOkResponse({description: 'Sign in success', type: SigninSuccessResponseDto})
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized access',
    type: SigninUnauthorizedResponseDto
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Unverified user',
    type: SigninUserUnverifiedResponseDto
  })
  async signin(@Body() signinData: SigninDto): Promise<SigninSuccessResponseDto | SigninUnauthorizedResponseDto | SigninUserUnverifiedResponseDto> {
    return await this.authService.signin(signinData);
  }

  @HttpCode(HttpStatus.OK)
  @Post(verification_otp)
  @ApiOperation({summary: 'Verify OTP'})
  @ApiBody({type: VerificationDto})
  @ApiOkResponse({description: 'OTP verification success', type: SigninSuccessResponseDto})
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'OTP verification failed',
    type: VerificationErrorResponseDto
  })
  async verificationOtp(@Body() EmailVerificationByOTPData: VerificationDto): Promise<SigninSuccessResponseDto | VerificationErrorResponseDto> {
    return await this.authService.verificationOtp(EmailVerificationByOTPData);
  }

  @HttpCode(HttpStatus.OK)
  @Post(resend_otp)
  @ApiOperation({summary: 'Resend OTP email'})
  @ApiBody({type: ResendDto})
  @ApiOkResponse({description: 'OTP email sent successfully', type: ResendSuccessResponseDto})
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'OTP email sending failed',
    type: ResendErrorResponseDto
  })
  async resend(@Body() ResendOTPData: ResendDto): Promise<ResendSuccessResponseDto | ResendErrorResponseDto> {
    return await this.authService.resend(ResendOTPData);
  }

  @HttpCode(HttpStatus.OK)
  @Post(forget_password_otp_send)
  @ApiOperation({
    summary: 'Forget password.service.ts OTP email send',
    description: `
      Password recovery steps:
      
      1. Call the Forget Password API to sent OTP via email({baseUrl}/auth/${forget_password_otp_send}).
      2. Verify the user's identity by entering the OTP received via email({baseUrl}/auth/${verification_otp}).
      3. Call the Change Password API to reset the password, providing the newPassword field in request body({baseUrl}/auth/${change_password}).
    `
  })
  @ApiBody({type: ForgetPasswordDto})
  @ApiOkResponse({description: 'OTP email sent successfully', type: ForgetPasswordSuccessResponseDto})
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'OTP email sending failed',
    type: ForgetPasswordErrorResponseDto
  })
  async forgetPassword(
    @Body()
    ForgetPasswordSendEmailForOTPData: ForgetPasswordDto
  ): Promise<ForgetPasswordSuccessResponseDto | ForgetPasswordErrorResponseDto> {
    return await this.authService.forgetPassword(ForgetPasswordSendEmailForOTPData);
  }

  @HttpCode(HttpStatus.OK)
  @UseGuards(JweJwtAccessTokenStrategy)
  @Post(change_password)
  @ApiOperation({
    summary: 'Change user password.service.ts',
    description: `
      1) For forget password only newPassword is required 
      2) For change password oldPassword & newPassword both fields are required
    `
  })
  @ApiBody({type: ChangePasswordDto})
  @ApiOkResponse({
    description: 'Password changed successfully',
    type: ChangePasswordSuccessResponseDto
  })
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'Failed to change password.service.ts',
    type: ChangePasswordErrorResponseDto
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Unverified user',
    type: ChangePasswordUnverifiedResponseDto
  })
  async changePassword(
    @Body() ChangePasswordData: ChangePasswordDto,
    @Req() req: Request
  ): Promise<ChangePasswordSuccessResponseDto | ChangePasswordErrorResponseDto | ChangePasswordUnverifiedResponseDto> {
    return await this.authService.changePassword(ChangePasswordData, req);
  }

  @UseGuards(JweJwtRefreshTokenStrategy)
  @HttpCode(HttpStatus.OK)
  @Get(REFRESH_TOKEN)
  @ApiOperation({summary: 'Refresh access token'})
  @ApiOkResponse({description: 'Access token refreshed successfully', type: RefreshTokenSuccessResponseDto})
  async refreshToken(@Req() req: Request): Promise<RefreshTokenSuccessResponseDto> {
    return await this.authService.refreshToken(req);
  }

  @Get('google')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({
    summary: 'Start Google OAuth flow',
    description:
      'Redirects to Google for authentication. This is handled externally by Google OAuth services. Run this URL in the browser (http://localhost:3000/auth/google).'
  })
  @ApiOkResponse({description: 'Initiates Google OAuth flow'})
  async googleAuth(): Promise<void> {}

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({
    summary: 'Google OAuth callback',
    description: 'Handles the callback after Google authentication. This endpoint processes the authentication result from Google.'
  })
  @ApiOkResponse({description: 'Authentication successful, returns user data and tokens'})
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Authentication failed due to invalid or expired credentials.'
  })
  async googleAuthRedirect(@Req() req) {
    return await this.authService.oAuthSignin(req.user);
  }

  @Get('facebook')
  @UseGuards(AuthGuard('facebook'))
  @ApiOperation({
    summary: 'Start Facebook OAuth flow',
    description:
      'Redirects to Facebook for authentication. This is handled externally by Facebook OAuth services. Run this URL in the browser (http://localhost:3000/auth/facebook).'
  })
  @ApiOkResponse({description: 'Initiates Facebook OAuth flow'})
  async facebookAuth(): Promise<void> {}

  @Get('facebook/callback')
  @UseGuards(AuthGuard('facebook'))
  @ApiOperation({
    summary: 'Facebook OAuth callback',
    description: 'Handles the callback after Facebook authentication. This endpoint processes the authentication result from Facebook.'
  })
  @ApiOkResponse({description: 'Authentication successful, returns user data and tokens'})
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Authentication failed due to invalid or expired credentials.'
  })
  async facebookAuthRedirect(@Req() req) {
    return await this.authService.oAuthSignin(req.user);
  }

  @HttpCode(HttpStatus.OK)
  @UseGuards(JweJwtAccessTokenStrategy) // Ensure the user is authenticated
  @Post(LOGOUT_ALL)
  @ApiOperation({summary: 'Logout user from all devices'})
  @ApiOkResponse({description: 'User logged out successfully'})
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Unauthorized access'
  })
  async logout(@Req() req: Request): Promise<{success: boolean; message: string}> {
    const userId = (req.user as {id: number}).id;
    const message = await this.logoutService.logoutFromAllDevices(userId);
    return {
      success: true,
      message: message
    };
  }
}
