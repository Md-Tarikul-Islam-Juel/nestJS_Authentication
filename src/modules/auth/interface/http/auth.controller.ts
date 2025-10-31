import {Body, Controller, Get, HttpCode, HttpStatus, Post, Req, UseGuards, UseInterceptors} from '@nestjs/common';
import {AuthGuard} from '@nestjs/passport';
import {ApiBody, ApiCreatedResponse, ApiOkResponse, ApiOperation, ApiResponse, ApiTags} from '@nestjs/swagger';
import {Request} from 'express';
import {JweJwtAccessTokenStrategy} from '../../../../modules/token/strategy/jwe-jwt-access-token.strategy';
import {JweJwtRefreshTokenStrategy} from '../../../../modules/token/strategy/jwe-jwt-refresh-token.strategy';
import {AUTH_ROUTES} from '../../../_shared/constants';
import {ChangePasswordDto, ForgetPasswordDto, ResendDto, SigninDto, SignupDto, VerificationDto} from '../../application/dto/auth-request.dto';
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
} from '../../application/dto/auth-response.dto';
import {AuthService} from '../../application/services/auth.service';
import {LogoutService} from '../../infrastructure/services/logout.service';
import {TrackLastActivityInterceptor} from './interceptors/track-last-activity.interceptor';

@ApiTags('Auth')
@Controller(AUTH_ROUTES.BASE)
@UseInterceptors(TrackLastActivityInterceptor)
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly logoutService: LogoutService
  ) {}

  @HttpCode(HttpStatus.CREATED)
  @Post(AUTH_ROUTES.SIGNUP)
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
  @Post(AUTH_ROUTES.SIGNIN)
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
  @Post(AUTH_ROUTES.VERIFY_OTP)
  @ApiOperation({summary: 'Verify OTP'})
  @ApiBody({type: VerificationDto})
  @ApiOkResponse({description: 'OTP verification success', type: SigninSuccessResponseDto})
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'OTP verification failed',
    type: VerificationErrorResponseDto
  })
  async verificationOtp(@Body() verificationData: VerificationDto): Promise<SigninSuccessResponseDto | VerificationErrorResponseDto> {
    return await this.authService.verificationOtp(verificationData);
  }

  @HttpCode(HttpStatus.OK)
  @Post(AUTH_ROUTES.RESEND_OTP)
  @ApiOperation({summary: 'Resend OTP email'})
  @ApiBody({type: ResendDto})
  @ApiOkResponse({description: 'OTP email sent successfully', type: ResendSuccessResponseDto})
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'OTP email sending failed',
    type: ResendErrorResponseDto
  })
  async resend(@Body() resendData: ResendDto): Promise<ResendSuccessResponseDto | ResendErrorResponseDto> {
    return await this.authService.resend(resendData);
  }

  @HttpCode(HttpStatus.OK)
  @Post(AUTH_ROUTES.FORGET_PASSWORD)
  @ApiOperation({
    summary: 'Forget password OTP email send',
    description: `
      Password recovery steps:
      
      1. Call the Forget Password API to sent OTP via email({baseUrl}/auth/${AUTH_ROUTES.FORGET_PASSWORD}).
      2. Verify the user's identity by entering the OTP received via email({baseUrl}/auth/${AUTH_ROUTES.VERIFY_OTP}).
      3. Call the Change Password API to reset the password, providing the newPassword field in request body({baseUrl}/auth/${AUTH_ROUTES.CHANGE_PASSWORD}).
    `
  })
  @ApiBody({type: ForgetPasswordDto})
  @ApiOkResponse({description: 'OTP email sent successfully', type: ForgetPasswordSuccessResponseDto})
  @ApiResponse({
    status: HttpStatus.BAD_REQUEST,
    description: 'OTP email sending failed',
    type: ForgetPasswordErrorResponseDto
  })
  async forgetPassword(@Body() forgetPasswordData: ForgetPasswordDto): Promise<ForgetPasswordSuccessResponseDto | ForgetPasswordErrorResponseDto> {
    return await this.authService.forgetPassword(forgetPasswordData);
  }

  @HttpCode(HttpStatus.OK)
  @UseGuards(JweJwtAccessTokenStrategy)
  @Post(AUTH_ROUTES.CHANGE_PASSWORD)
  @ApiOperation({
    summary: 'Change user password',
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
    description: 'Failed to change password',
    type: ChangePasswordErrorResponseDto
  })
  @ApiResponse({
    status: HttpStatus.FORBIDDEN,
    description: 'Unverified user',
    type: ChangePasswordUnverifiedResponseDto
  })
  async changePassword(
    @Body() changePasswordData: ChangePasswordDto,
    @Req() req: Request
  ): Promise<ChangePasswordSuccessResponseDto | ChangePasswordErrorResponseDto | ChangePasswordUnverifiedResponseDto> {
    return await this.authService.changePassword(changePasswordData, req);
  }

  @UseGuards(JweJwtRefreshTokenStrategy)
  @HttpCode(HttpStatus.OK)
  @Get(AUTH_ROUTES.REFRESH_TOKEN)
  @ApiOperation({summary: 'Refresh access token'})
  @ApiOkResponse({description: 'Access token refreshed successfully', type: RefreshTokenSuccessResponseDto})
  async refreshToken(@Req() req: Request): Promise<RefreshTokenSuccessResponseDto> {
    return await this.authService.refreshToken(req);
  }

  @Get('google')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({
    summary: 'Start Google OAuth flow',
    description: 'Redirects to Google for authentication. This is handled externally by Google OAuth services.'
  })
  @ApiOkResponse({description: 'Initiates Google OAuth flow'})
  async googleAuth(): Promise<void> {}

  @Get('google/callback')
  @UseGuards(AuthGuard('google'))
  @ApiOperation({
    summary: 'Google OAuth callback',
    description: 'Handles the callback after Google authentication.'
  })
  @ApiOkResponse({description: 'Authentication successful, returns user data and tokens'})
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Authentication failed due to invalid or expired credentials.'
  })
  async googleAuthRedirect(@Req() req): Promise<SigninSuccessResponseDto> {
    return await this.authService.oAuthSignin(req.user);
  }

  @Get('facebook')
  @UseGuards(AuthGuard('facebook'))
  @ApiOperation({
    summary: 'Start Facebook OAuth flow',
    description: 'Redirects to Facebook for authentication. This is handled externally by Facebook OAuth services.'
  })
  @ApiOkResponse({description: 'Initiates Facebook OAuth flow'})
  async facebookAuth(): Promise<void> {}

  @Get('facebook/callback')
  @UseGuards(AuthGuard('facebook'))
  @ApiOperation({
    summary: 'Facebook OAuth callback',
    description: 'Handles the callback after Facebook authentication.'
  })
  @ApiOkResponse({description: 'Authentication successful, returns user data and tokens'})
  @ApiResponse({
    status: HttpStatus.UNAUTHORIZED,
    description: 'Authentication failed due to invalid or expired credentials.'
  })
  async facebookAuthRedirect(@Req() req): Promise<SigninSuccessResponseDto> {
    return await this.authService.oAuthSignin(req.user);
  }

  @HttpCode(HttpStatus.OK)
  @UseGuards(JweJwtAccessTokenStrategy)
  @Post(AUTH_ROUTES.LOGOUT_ALL)
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
