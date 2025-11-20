import { Field, Int, ObjectType } from '@nestjs/graphql';
import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsNotEmpty, IsNumber, IsString } from 'class-validator';
import { BaseResponseDto, Tokens, UserData } from './auth-base.dto';

// =================================================================
//----------------------------SIGN UP-------------------------------
// =================================================================
@ObjectType()
export class OtpInfoDto {
  @ApiProperty({description: 'Timeout value for OTP', example: 5})
  @Field(() => Int)
  @IsNumber()
  timeout!: number;

  @ApiProperty({description: 'Unit of time for OTP timeout', example: 'mins'})
  @Field()
  @IsString()
  unit!: string;
}

// Define SignupResponseUserDto next
@ObjectType()
export class SignupResponseUserDto {
  @ApiProperty({description: 'User ID'})
  @Field(() => Int)
  @IsNotEmpty()
  id!: number;

  @ApiProperty({description: 'User email address'})
  @Field()
  @IsEmail()
  @IsNotEmpty()
  email!: string;

  @ApiProperty({description: 'User first name'})
  @Field({nullable: true})
  @IsString()
  @IsNotEmpty()
  firstName!: string;

  @ApiProperty({description: 'User last name'})
  @Field({nullable: true})
  @IsString()
  @IsNotEmpty()
  lastName!: string;

  @ApiProperty({description: 'Account creation timestamp', example: '2025-10-31T13:55:58.802Z', required: false})
  @Field({nullable: true})
  createdAt?: Date;
}

// Define SignupResponseDataDto before SignupSuccessResponseDto
@ObjectType()
export class SignupResponseDataDto {
  @ApiProperty({description: 'User data', type: () => SignupResponseUserDto})
  @Field(() => SignupResponseUserDto)
  user!: SignupResponseUserDto;

  @ApiProperty({description: 'OTP information for verification', type: () => OtpInfoDto})
  @Field(() => OtpInfoDto, {nullable: true})
  otp?: OtpInfoDto;
}

// Now define SignupSuccessResponseDto with reference to SignupResponseDataDto
@ObjectType()
export class SignupSuccessResponseDto extends BaseResponseDto {
  @ApiProperty({description: 'Data of the signed-up user and OTP information', type: () => SignupResponseDataDto})
  @Field(() => SignupResponseDataDto)
  data!: SignupResponseDataDto;
}

// Define the SignupUserAlreadyExistResponseDto at the end
@ObjectType()
export class SignupUserAlreadyExistResponseDto extends BaseResponseDto {
  @ApiProperty({description: 'Message indicating the reason for failure', example: 'User already exists'})
  @Field()
  message: string = 'User already exists';
}
// =================================================================
//----------------------------SIGN IN-------------------------------
// =================================================================
@ObjectType()
export class SigninResponseDataDto {
  @Field(() => SignupResponseUserDto)
  user!: SignupResponseUserDto;
}

@ObjectType()
export class SigninSuccessResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Tokens object containing access and refresh tokens',
    type: Tokens,
    required: false
  })
  @Field(() => Tokens, {nullable: true})
  tokens?: Tokens;

  @ApiProperty({description: 'Data of the signed-in user', type: () => UserData, required: false})
  @Field(() => SigninResponseDataDto, {nullable: true})
  data?: SigninResponseDataDto;

  @ApiProperty({
    description: 'MFA information, returned if MFA is required',
    required: false // Optional field, present only when MFA is required
  })
  @Field({nullable: true})
  mfa?: {
    enabled: boolean;
    type: string;
  }; // Optional MFA field, only present when MFA is required
}

@ObjectType()
export class SigninUnauthorizedResponseDto extends BaseResponseDto {
  @ApiProperty({description: 'Message indicating unauthorized access', example: 'Unauthorized'})
  @Field()
  message: string = 'Unauthorized';
}

@ObjectType()
export class SigninUserUnverifiedResponseDto extends BaseResponseDto {
  @ApiProperty({description: 'Message indicating Unverified user', example: 'Please verify your user'})
  @Field()
  message: string = 'Please verify your user';
}

@ObjectType()
export class SignInResponseUserDto {
  @IsNotEmpty()
  @Field(() => Int)
  id!: number;

  @IsEmail()
  @IsNotEmpty()
  @Field()
  email!: string;

  @IsString()
  @IsNotEmpty()
  @Field()
  firstName!: string;

  @IsString()
  @IsNotEmpty()
  @Field()
  lastName!: string;
}

// =================================================================
//-------------------------VERIFICATION-----------------------------
// =================================================================
@ObjectType()
export class VerificationErrorResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Message indicating the reason for OTP verification failure',
    example: 'OTP verification failed'
  })
  @Field()
  message: string = 'OTP verification failed';
}

// =================================================================
//-----------------------------RESEND-------------------------------
// =================================================================
@ObjectType()
export class ResendResponseDataDto {
  @ApiProperty({description: 'OTP information for verification', type: () => OtpInfoDto})
  @Field(() => OtpInfoDto)
  otp!: OtpInfoDto;
}

@ObjectType()
export class ResendSuccessResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Message indicating the result of the OTP email sending process',
    example: 'OTP email sent'
  })
  @Field()
  message: string = 'OTP email sent';

  @ApiProperty({
    description: 'Response data containing OTP information',
    type: () => ResendResponseDataDto
  })
  @Field(() => ResendResponseDataDto)
  data!: ResendResponseDataDto;
}

@ObjectType()
export class ResendErrorResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Message indicating the reason for OTP email sending failure',
    example: 'Failed to send OTP email'
  })
  @Field()
  message: string = 'Failed to send OTP email';
}

// =================================================================
//------------------------FORGET PASSWORD---------------------------
// =================================================================
@ObjectType()
export class ForgetPasswordResponseDataDto {
  @ApiProperty({description: 'OTP information for verification', type: () => OtpInfoDto})
  @Field(() => OtpInfoDto)
  otp!: OtpInfoDto;
}

@ObjectType()
export class ForgetPasswordSuccessResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Message indicating the result of the OTP email sending process',
    example: 'OTP email sent'
  })
  @Field()
  message: string = 'OTP email sent';

  @ApiProperty({
    description: 'Response data containing OTP information',
    type: () => ForgetPasswordResponseDataDto
  })
  @Field(() => ForgetPasswordResponseDataDto)
  data!: ForgetPasswordResponseDataDto;
}

@ObjectType()
export class ForgetPasswordErrorResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Message indicating the reason for OTP email sending failure',
    example: 'Failed to send OTP email'
  })
  @Field()
  message: string = 'Failed to send OTP email';
}

// =================================================================
//------------------------CHANGE PASSWORD---------------------------
// =================================================================
@ObjectType()
export class ChangePasswordSuccessResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Message indicating the result of the password change',
    example: 'Your password has been updated'
  })
  @Field()
  message: string = 'Your password has been updated';
}

@ObjectType()
export class ChangePasswordErrorResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Error message indicating the reason for the password change failure',
    example: 'Failed to change password'
  })
  @Field()
  message: string = 'Failed to change password';
}

@ObjectType()
export class ChangePasswordUnverifiedResponseDto extends BaseResponseDto {
  @ApiProperty({description: 'Message indicating Unverified user', example: 'Please verify your user'})
  @Field()
  message: string = 'Please verify your user';
}

// =================================================================
//-----------------------REFRESH TOKEN------------------------------
// =================================================================
@ObjectType()
export class RefreshTokenSuccessResponseDto extends BaseResponseDto {
  @ApiProperty({
    description: 'Tokens object containing access and refresh tokens',
    type: Tokens
  })
  @Field(() => Tokens)
  tokens!: Tokens;
}
