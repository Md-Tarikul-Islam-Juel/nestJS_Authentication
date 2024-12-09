import {IsString, IsOptional, IsIn, Matches, IsNotEmpty, IsBoolean} from 'class-validator';
import {ApiProperty} from '@nestjs/swagger';
import {EmailDto} from './auth.base.dto';
import * as dotenv from 'dotenv';
import {PasswordValidation} from '../Decorators/password-decorator.decorator';

dotenv.config();

// =================================================================
//----------------------------SIGN UP-------------------------------
// =================================================================
export class SignupDto extends EmailDto {
  @ApiProperty({example: 'password', description: 'The password for the account'})
  @PasswordValidation()
  password: string;

  @ApiProperty({example: 'John', description: 'The first name of the user', required: false})
  @IsString()
  @IsOptional()
  firstName?: string;

  @ApiProperty({example: 'Doe', description: 'The last name of the user', required: false})
  @IsString()
  @IsOptional()
  lastName?: string;

  @ApiProperty({
    example: false,
    description: 'Enable MFA for the account',
    required: false,
    default: false
  })
  @IsBoolean()
  @IsOptional()
  mfaEnabled?: boolean;
}

// =================================================================
//----------------------------SIGN IN-------------------------------
// =================================================================
export class SigninDto extends EmailDto {
  @ApiProperty({example: 'password', description: 'The password.service.ts for the account'})
  @IsString()
  @IsNotEmpty({message: 'Password is required'})
  password: string;
}

// =================================================================
//----------------------------OAUTH---------------------------------
// =================================================================
export class OAuthDto extends EmailDto {
  @ApiProperty({example: 'John', description: 'The first name of the user', required: false})
  @IsString()
  @IsOptional()
  firstName: string;

  @ApiProperty({example: 'Doe', description: 'The last name of the user', required: false})
  @IsString()
  @IsOptional()
  lastName: string;

  @ApiProperty({example: 'google', description: 'The login source of the user (google or facebook)', required: false})
  @IsString()
  @IsOptional()
  @IsIn(['google', 'facebook'], {message: 'Login source must be either google or facebook'})
  loginSource: string = 'google'; // Default value set to 'google'

  @ApiProperty({
    example: false,
    description: 'Enable MFA for the account',
    required: false,
    default: false
  })
  @IsBoolean()
  @IsOptional()
  mfaEnabled?: boolean;
}

// =================================================================
//-----------------------------RESEND-------------------------------
// =================================================================
export class ResendDto extends EmailDto {}

// =================================================================
//-------------------------VERIFICATION-----------------------------
// =================================================================
export class VerificationDto extends EmailDto {
  @ApiProperty({
    example: '123456',
    description: 'A six-digit OTP (One-Time Password)'
  })
  @Matches(/^\d{6}$/, {
    message: 'OTP must be a 6-digit number'
  })
  otp: string;
}

// =================================================================
//------------------------FORGET PASSWORD---------------------------
// =================================================================
export class ForgetPasswordDto extends EmailDto {}

// =================================================================
//------------------------CHANGE PASSWORD---------------------------
// =================================================================
export class ChangePasswordDto {
  @ApiProperty({
    example: 'oldPassword123',
    description: 'The old password.service.ts (if changing)'
  })
  @IsString()
  @IsOptional()
  @PasswordValidation()
  oldPassword?: string;

  @ApiProperty({
    example: 'newPassword123',
    description: 'The new password.service.ts'
  })
  @IsString()
  @IsNotEmpty({message: 'New password.service.ts is required'})
  @PasswordValidation()
  newPassword: string;
}
