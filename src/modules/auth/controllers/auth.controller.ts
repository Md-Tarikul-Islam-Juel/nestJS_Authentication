import { Body, Controller, Get, HttpCode, HttpStatus, Inject, Post, Req, UseGuards } from '@nestjs/common';
import {AuthGuard} from '@nestjs/passport';
import {Request} from 'express';
import {AuthService} from '../services/auth.service';
import {LoggerService} from '../../logger/logger.service';
import {
    ChangePasswordDto,
    ForgetPasswordDto,
    ResendDto,
    SigninDto,
    SignupDto,
    VerificationDto
} from "../dto/authRequest.dto";
import {ApiBody, ApiCreatedResponse, ApiOkResponse, ApiOperation, ApiResponse, ApiTags} from "@nestjs/swagger"

import {
    ChangePasswordErrorResponseDto,
    ChangePasswordSuccessResponseDto, ChangePasswordUnverifiedResponseDto,
    ForgetPasswordErrorResponseDto,
    ForgetPasswordSuccessResponseDto, RefreshTokenSuccessResponseDto,
    ResendErrorResponseDto,
    ResendSuccessResponseDto,
    SigninSuccessResponseDto, SigninUnauthorizedResponseDto, SigninUserUnverifiedResponseDto,
    SignupSuccessResponseDto,
    SignupUserAlreadyExistResponseDto, VerificationErrorResponseDto, VerificationSuccessResponseDto,
} from '../dto/authRespnse.dto';
import {
    AUTH,
    change_password,
    forget_password_otp_send, REFRESH_TOKEN,
    resend_otp,
    SIGNIN,
    SIGNUP,
    verification_otp,
} from '../utils/string';


@ApiTags('Auth')
@Controller(AUTH)
export class AuthController {
    constructor(
        @Inject(AuthService)
        private readonly authService: AuthService,
        private logger: LoggerService,
    ) {
    }

    @HttpCode(HttpStatus.CREATED)
    @Post(SIGNUP)
    @ApiOperation({summary: 'Sign up user'})
    @ApiBody({type: SignupDto})
    @ApiCreatedResponse({description: "Sign up success", type: SignupSuccessResponseDto})
    @ApiResponse({
        status: HttpStatus.CONFLICT,
        description: "User already exist",
        type: SignupUserAlreadyExistResponseDto,
    })
    async signup(@Body() signupData: SignupDto): Promise<SignupSuccessResponseDto | SignupUserAlreadyExistResponseDto> {
        this.logger.info(`--------------------------------`, `${this.constructor.name}.signup():`);
        this.logger.info(
            `signup data: ${JSON.stringify(signupData)}`,
            `${this.constructor.name}.signup():`,
        );
        this.logger.info(`--------------------------------`, `${this.constructor.name}.signup():`);

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
        type: SigninUnauthorizedResponseDto,
    })
    @ApiResponse({
        status: HttpStatus.FORBIDDEN,
        description: 'Unverified user',
        type: SigninUserUnverifiedResponseDto,
    })
    async signin(@Body() signinData: SigninDto): Promise<SigninSuccessResponseDto | SigninUnauthorizedResponseDto | SigninUserUnverifiedResponseDto> {
        return await this.authService.signin(signinData);
    }

    @HttpCode(HttpStatus.OK)
    @Post(verification_otp)
    @ApiOperation({summary: 'Verify OTP'})
    @ApiBody({type: VerificationDto})
    @ApiOkResponse({description: 'OTP verification success', type: VerificationSuccessResponseDto})
    @ApiResponse({
        status: HttpStatus.UNAUTHORIZED,
        description: 'OTP verification failed',
        type: VerificationErrorResponseDto
    })
    async verificationOtp(
        @Body() EmailVerificationByOTPData: VerificationDto,
    ): Promise<VerificationSuccessResponseDto | VerificationErrorResponseDto> {
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
        summary: 'Forget password OTP email send',
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
            ForgetPasswordSendEmailForOTPData: ForgetPasswordDto,
    ): Promise<ForgetPasswordSuccessResponseDto | ForgetPasswordErrorResponseDto> {
        return await this.authService.forgetPassword(ForgetPasswordSendEmailForOTPData);
    }

    @HttpCode(HttpStatus.OK)
    @UseGuards(AuthGuard('jwt_accessToken_guard'))
    @Post(change_password)
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
        type: ChangePasswordSuccessResponseDto,
    })
    @ApiResponse({
        status: HttpStatus.BAD_REQUEST,
        description: 'Failed to change password',
        type: ChangePasswordErrorResponseDto,
    })
    @ApiResponse({
        status: HttpStatus.FORBIDDEN,
        description: 'Unverified user',
        type: ChangePasswordUnverifiedResponseDto,
    })
    async ChangePassword(
        @Body() ChangePasswordData: ChangePasswordDto,
        @Req() req: Request,
    ): Promise<ChangePasswordSuccessResponseDto | ChangePasswordErrorResponseDto | ChangePasswordUnverifiedResponseDto> {
        return await this.authService.ChangePassword(ChangePasswordData, req);
    }


    @UseGuards(AuthGuard('jwt_refreshToken_guard'))
    @HttpCode(HttpStatus.OK)
    @Get(REFRESH_TOKEN)
    @ApiOperation({ summary: 'Refresh access token' })
    @ApiOkResponse({ description: 'Access token refreshed successfully', type: RefreshTokenSuccessResponseDto })
    async refreshToken(@Req() req: Request,): Promise<RefreshTokenSuccessResponseDto> {
        return await this.authService.refreshToken(req);
    }
}

