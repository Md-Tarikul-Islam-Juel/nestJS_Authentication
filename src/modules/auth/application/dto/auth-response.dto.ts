import {ApiProperty} from '@nestjs/swagger';
import {IsEmail, IsNotEmpty, IsNumber, IsString} from 'class-validator';
import {BaseResponseDto, Tokens, UserData} from './auth-base.dto';

// =================================================================
//----------------------------SIGN UP-------------------------------
// =================================================================
export class OtpInfoDto {
  @ApiProperty({description: 'Timeout value for OTP', example: 5})
  @IsNumber()
  timeout: number;

  @ApiProperty({description: 'Unit of time for OTP timeout', example: 'mins'})
  @IsString()
  unit: string;
}

// Define SignupResponseUserDto next
export class SignupResponseUserDto {
  @ApiProperty({description: 'User ID'})
  @IsNotEmpty()
  id: number;

  @ApiProperty({description: 'User email address'})
  @IsEmail()
  @IsNotEmpty()
  email: string;

  @ApiProperty({description: 'User first name'})
  @IsString()
  @IsNotEmpty()
  firstName: string;

  @ApiProperty({description: 'User last name'})
  @IsString()
  @IsNotEmpty()
  lastName: string;

  @ApiProperty({description: 'Account creation timestamp', example: '2025-10-31T13:55:58.802Z', required: false})
  createdAt?: Date;
}

// Define SignupResponseDataDto before SignupSuccessResponseDto
export class SignupResponseDataDto {
  @ApiProperty({description: 'User data', type: () => SignupResponseUserDto})
  user: SignupResponseUserDto;

  @ApiProperty({description: 'OTP information for verification', type: () => OtpInfoDto})
  otp: OtpInfoDto;
}

// Now define SignupSuccessResponseDto with reference to SignupResponseDataDto
export class SignupSuccessResponseDto extends BaseResponseDto {
  @ApiProperty({description: 'Data of the signed-up user and OTP information', type: () => SignupResponseDataDto})
  data: SignupResponseDataDto;
}

// Define the SignupUserAlreadyExistResponseDto at the end
export class SignupUserAlreadyExistResponseDto extends BaseResponseDto {
  @ApiProperty({description: 'Message indicating the reason for failure', example: 'User already exists'})
  message: string = 'User already exists';
}
// =================================================================
//----------------------------SIGN IN-------------------------------
// =================================================================
export class SigninSuccessResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Tokens object containing access and refresh tokens',
    type: Tokens,
    required: false
  })
  tokens?: Tokens;

  @ApiProperty({description: 'Data of the signed-in user', type: () => UserData, required: false})
  data?: {user: UserData};

  @ApiProperty({
    description: 'MFA information, returned if MFA is required',
    required: false // Optional field, present only when MFA is required
  })
  mfa?: {
    enabled: boolean;
    type: string;
  }; // Optional MFA field, only present when MFA is required
}

export class SigninUnauthorizedResponseDto extends BaseResponseDto {
  @ApiProperty({description: 'Message indicating unauthorized access', example: 'Unauthorized'})
  message: string = 'Unauthorized';
}

export class SigninUserUnverifiedResponseDto extends BaseResponseDto {
  @ApiProperty({description: 'Message indicating Unverified user', example: 'Please verify your user'})
  message: string = 'Please verify your user';
}

export class SignInResponseUserDto {
  @IsNotEmpty()
  id: number;

  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  firstName: string;

  @IsString()
  @IsNotEmpty()
  lastName: string;
}

// =================================================================
//-------------------------VERIFICATION-----------------------------
// =================================================================
export class VerificationErrorResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Message indicating the reason for OTP verification failure',
    example: 'OTP verification failed'
  })
  message: string = 'OTP verification failed';
}

// =================================================================
//-----------------------------RESEND-------------------------------
// =================================================================
export class ResendResponseDataDto {
  @ApiProperty({description: 'OTP information for verification', type: () => OtpInfoDto})
  otp: OtpInfoDto;
}

export class ResendSuccessResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Message indicating the result of the OTP email sending process',
    example: 'OTP email sent'
  })
  message: string = 'OTP email sent';

  @ApiProperty({
    description: 'Response data containing OTP information',
    type: () => ResendResponseDataDto
  })
  data: ResendResponseDataDto;
}

export class ResendErrorResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Message indicating the reason for OTP email sending failure',
    example: 'Failed to send OTP email'
  })
  message: string = 'Failed to send OTP email';
}

// =================================================================
//------------------------FORGET PASSWORD---------------------------
// =================================================================
// export class ForgetPasswordSuccessResponseDto extends BaseResponseDto {
//   @ApiProperty({
//     description: 'Message indicating the result of the OTP email sending process',
//     example: 'OTP email sent'
//   })
//   message: string = 'OTP email sent';
// }

export class ForgetPasswordResponseDataDto {
  @ApiProperty({description: 'OTP information for verification', type: () => OtpInfoDto})
  otp: OtpInfoDto;
}

export class ForgetPasswordSuccessResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Message indicating the result of the OTP email sending process',
    example: 'OTP email sent'
  })
  message: string = 'OTP email sent';

  @ApiProperty({
    description: 'Response data containing OTP information',
    type: () => ForgetPasswordResponseDataDto
  })
  data: ForgetPasswordResponseDataDto;
}

export class ForgetPasswordErrorResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Message indicating the reason for OTP email sending failure',
    example: 'Failed to send OTP email'
  })
  message: string = 'Failed to send OTP email';
}

// =================================================================
//------------------------CHANGE PASSWORD---------------------------
// =================================================================
export class ChangePasswordSuccessResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Message indicating the result of the password.service.ts change',
    example: 'Your password.service.ts has been updated'
  })
  message: string = 'Your password.service.ts has been updated';
}

export class ChangePasswordErrorResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Error message indicating the reason for the password.service.ts change failure',
    example: 'Failed to change password.service.ts'
  })
  message: string = 'Failed to change password.service.ts';
}

export class ChangePasswordUnverifiedResponseDto extends BaseResponseDto {
  @ApiProperty({description: 'Message indicating Unverified user', example: 'Please verify your user'})
  message: string = 'Please verify your user';
}

// =================================================================
//-----------------------REFRESH TOKEN------------------------------
// =================================================================
export class RefreshTokenSuccessResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Tokens object containing access and refresh tokens',
    type: Tokens
  })
  tokens: Tokens;
}
