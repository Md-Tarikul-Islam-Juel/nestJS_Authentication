import { ApiProperty } from '@nestjs/swagger';
import { BaseResponseDto, Tokens, UserData } from './auth.base.dto';

// =================================================================
//----------------------------SIGN UP-------------------------------
// =================================================================
export class SignupSuccessResponseDto extends BaseResponseDto {
  @ApiProperty({ description: 'Data of the signed-up user', type: () => UserData })
  data: { user: UserData };
}

export class SignupUserAlreadyExistResponseDto extends BaseResponseDto {
  @ApiProperty({ description: 'Message indicating the reason for failure', example: 'User already exists' })
  message: string = 'User already exists';
}

// =================================================================
//----------------------------SIGN IN-------------------------------
// =================================================================
export class SigninSuccessResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Tokens object containing access and refresh tokens',
    type: Tokens,
  })
  tokens: Tokens;

  @ApiProperty({ description: 'Data of the signed-in user', type: () => UserData })
  data: { user: UserData };
}

export class SigninUnauthorizedResponseDto extends BaseResponseDto {
  @ApiProperty({ description: 'Message indicating unauthorized access', example: 'Unauthorized' })
  message: string = 'Unauthorized';
}

export class SigninUserUnverifiedResponseDto extends BaseResponseDto {
  @ApiProperty({ description: 'Message indicating Unverified user', example: 'Please verify your user' })
  message: string = 'Please verify your user';
}

// =================================================================
//-------------------------VERIFICATION-----------------------------
// =================================================================
export class VerificationErrorResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Message indicating the reason for OTP verification failure',
    example: 'OTP verification failed',
  })
  message: string = 'OTP verification failed';
}

// =================================================================
//-----------------------------RESEND-------------------------------
// =================================================================
export class ResendSuccessResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Message indicating the result of the OTP email sending process',
    example: 'OTP email sent',
  })
  message: string = 'OTP email sent';
}

export class ResendErrorResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Message indicating the reason for OTP email sending failure',
    example: 'Failed to send OTP email',
  })
  message: string = 'Failed to send OTP email';
}

// =================================================================
//------------------------FORGET PASSWORD---------------------------
// =================================================================
export class ForgetPasswordSuccessResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Message indicating the result of the OTP email sending process',
    example: 'OTP email sent',
  })
  message: string = 'OTP email sent';
}

export class ForgetPasswordErrorResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Message indicating the reason for OTP email sending failure',
    example: 'Failed to send OTP email',
  })
  message: string = 'Failed to send OTP email';
}

// =================================================================
//------------------------CHANGE PASSWORD---------------------------
// =================================================================
export class ChangePasswordSuccessResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Message indicating the result of the password change',
    example: 'Your password has been updated',
  })
  message: string = 'Your password has been updated';
}

export class ChangePasswordErrorResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Error message indicating the reason for the password change failure',
    example: 'Failed to change password',
  })
  message: string = 'Failed to change password';
}

export class ChangePasswordUnverifiedResponseDto extends BaseResponseDto {
  @ApiProperty({ description: 'Message indicating Unverified user', example: 'Please verify your user' })
  message: string = 'Please verify your user';
}

// =================================================================
//-----------------------REFRESH TOKEN------------------------------
// =================================================================
export class RefreshTokenSuccessResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Tokens object containing access and refresh tokens',
    type: Tokens,
  })
  tokens: Tokens;
}
