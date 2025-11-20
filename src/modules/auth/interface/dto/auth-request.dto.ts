import { Field, InputType } from '@nestjs/graphql';
import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsEmail, IsIn, IsNotEmpty, IsOptional, IsString, Length, Matches, MinLength } from 'class-validator';
import { PasswordValidation } from '../validators/password-decorator.decorator';
import { EmailDto } from './auth-base.dto';

// =================================================================
//----------------------------SIGN UP-------------------------------
// =================================================================
@InputType()
export class SignupDto extends EmailDto {
  @ApiProperty({example: 'password', description: 'The password for the account'})
  @Field()
  @PasswordValidation()
  password!: string;

  @ApiProperty({example: 'John', description: 'The first name of the user', required: false})
  @Field({nullable: true})
  @IsString()
  @IsOptional()
  firstName?: string;

  @ApiProperty({example: 'Doe', description: 'The last name of the user', required: false})
  @Field({nullable: true})
  @IsString()
  @IsOptional()
  lastName?: string;

  @ApiProperty({
    example: false,
    description: 'Enable MFA for the account',
    required: false,
    default: false
  })
  @Field({nullable: true, defaultValue: false})
  @IsBoolean()
  @IsOptional()
  mfaEnabled?: boolean;
}

// =================================================================
//----------------------------SIGN IN-------------------------------
// =================================================================
@InputType()
export class SigninDto extends EmailDto {
  @ApiProperty({example: 'password', description: 'The password for the account'})
  @Field()
  @IsString()
  @IsNotEmpty({message: 'Password is required'})
  password!: string;
}

// =================================================================
//----------------------------OAUTH---------------------------------
// =================================================================
@InputType()
export class OAuthDto extends EmailDto {
  @ApiProperty({example: 'John', description: 'The first name of the user', required: false})
  @Field()
  @IsString()
  @IsOptional()
  firstName!: string;

  @ApiProperty({example: 'Doe', description: 'The last name of the user', required: false})
  @Field()
  @IsString()
  @IsOptional()
  lastName!: string;

  @ApiProperty({example: 'google', description: 'The login source of the user (google or facebook)', required: false})
  @Field()
  @IsString()
  @IsOptional()
  @IsIn(['google', 'facebook'], {message: 'Login source must be either google or facebook'})
  loginSource: string = 'google';

  @ApiProperty({
    example: false,
    description: 'Enable MFA for the account',
    required: false,
    default: false
  })
  @Field({nullable: true, defaultValue: false})
  @IsBoolean()
  @IsOptional()
  mfaEnabled?: boolean;
}

// =================================================================
//-----------------------------RESEND-------------------------------
// =================================================================
@InputType()
export class ResendDto extends EmailDto {}

// =================================================================
//-------------------------VERIFICATION-----------------------------
// =================================================================
@InputType()
export class VerificationDto extends EmailDto {
  @ApiProperty({
    example: '123456',
    description: 'A six-digit OTP (One-Time Password)'
  })
  @Field()
  @Matches(/^\d{6}$/, {
    message: 'OTP must be a 6-digit number'
  })
  otp!: string;
}

// =================================================================
//------------------------FORGET PASSWORD---------------------------
// =================================================================
@InputType()
export class ForgetPasswordDto extends EmailDto {}

// =================================================================
//------------------------CHANGE PASSWORD---------------------------
// =================================================================
@InputType()
export class ChangePasswordDto {
  @ApiProperty({
    example: 'oldPassword123',
    description: 'The old password (if changing)'
  })
  @Field()
  @IsString()
  @IsOptional()
  @PasswordValidation()
  oldPassword?: string;

  @ApiProperty({
    example: 'newPassword123',
    description: 'The new password'
  })
  @Field()
  @IsString()
  @IsNotEmpty({message: 'New password is required'})
  @PasswordValidation()
  newPassword!: string;
}

@InputType()
export class RefreshTokenDto {
  @Field()
  @IsString()
  refreshToken!: string;
}

@InputType()
export class ResetPasswordDto {
  @Field()
  @IsEmail()
  email!: string;

  @Field()
  @IsString()
  @Length(6, 6)
  otp!: string;

  @Field()
  @IsString()
  @MinLength(8)
  newPassword!: string;
}
