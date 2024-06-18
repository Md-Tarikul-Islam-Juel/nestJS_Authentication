import { IsString, IsOptional, IsIn, Matches, IsNotEmpty } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { EmailDto } from './auth.base.dto';

// =================================================================
//----------------------------SIGN UP-------------------------------
// =================================================================
export class SignupDto extends EmailDto {
  @ApiProperty({ example: 'password', description: 'The password for the account' })
  @IsString()
  @IsNotEmpty({ message: 'Password is required' })
  password: string;

  @ApiProperty({ example: 'John', description: 'The first name of the user', required: false })
  @IsString()
  @IsOptional()
  firstName?: string;

  @ApiProperty({ example: 'Doe', description: 'The last name of the user', required: false })
  @IsString()
  @IsOptional()
  lastName?: string;
}

// =================================================================
//----------------------------SIGN IN-------------------------------
// =================================================================
export class SigninDto extends EmailDto {
  @ApiProperty({ example: 'password', description: 'The password for the account' })
  @IsString()
  @IsNotEmpty({ message: 'Password is required' })
  password: string;
}

// =================================================================
//----------------------------OAUTH---------------------------------
// =================================================================
export class OAuthDto extends EmailDto {
  @ApiProperty({ example: 'John', description: 'The first name of the user', required: false })
  @IsString()
  @IsOptional()
  firstName: string;

  @ApiProperty({ example: 'Doe', description: 'The last name of the user', required: false })
  @IsString()
  @IsOptional()
  lastName: string;

  @ApiProperty({ example: 'google', description: 'The login source of the user (google or facebook)', required: false })
  @IsString()
  @IsOptional()
  @IsIn(['google', 'facebook'], { message: 'Login source must be either google or facebook' })
  loginSource: string = 'google'; // Default value set to 'google'
}

// =================================================================
//-----------------------------RESEND-------------------------------
// =================================================================
export class ResendDto extends EmailDto {
}

// =================================================================
//-------------------------VERIFICATION-----------------------------
// =================================================================
export class VerificationDto extends EmailDto {
  @ApiProperty({
    example: '123456',
    description: 'A six-digit OTP (One-Time Password)',
  })
  @Matches(/^\d{6}$/, {
    message: 'OTP must be a 6-digit number',
  })
  otp: string;
}

// =================================================================
//------------------------FORGET PASSWORD---------------------------
// =================================================================
export class ForgetPasswordDto extends EmailDto {
}

// =================================================================
//------------------------CHANGE PASSWORD---------------------------
// =================================================================
export class ChangePasswordDto {
  @ApiProperty({
    example: 'oldPassword123',
    description: 'The old password (if changing)',
  })
  @IsString()
  @IsOptional()
  oldPassword?: string;

  @ApiProperty({
    example: 'newPassword123',
    description: 'The new password',
  })
  @IsString()
  @IsNotEmpty({ message: 'New password is required' })
  newPassword: string;
}
