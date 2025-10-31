import {ApiProperty} from '@nestjs/swagger';
import {IsEmail, IsNotEmpty, IsOptional, IsString, Matches} from 'class-validator';

export class EmailDto {
  @ApiProperty({example: 'user@example.com', description: 'The email of the user'})
  @IsEmail({}, {message: 'Email must be a valid email address'})
  @IsNotEmpty({message: 'Email is required'})
  email: string;
}

export class PasswordDto {
  @ApiProperty({example: 'password', description: 'The password for the account'})
  @IsString()
  @IsNotEmpty({message: 'Password is required'})
  password: string;
}

export class NameDto {
  @ApiProperty({example: 'John', description: 'The first name of the user', required: false})
  @IsString()
  @IsOptional()
  firstName?: string;

  @ApiProperty({example: 'Doe', description: 'The last name of the user', required: false})
  @IsString()
  @IsOptional()
  lastName?: string;
}

export class OtpDto {
  @ApiProperty({
    example: '123456',
    description: 'A six-digit OTP (One-Time Password)'
  })
  @Matches(/^\d{6}$/, {
    message: 'OTP must be a 6-digit number'
  })
  otp: string;
}

export class BaseResponseDto {
  @ApiProperty({description: 'Indicates if the operation was successful', example: true})
  success: boolean;

  @ApiProperty({description: 'Message indicating the result of the operation', example: 'Operation successful'})
  message: string;
}

export class Tokens {
  @ApiProperty({
    description: 'Access token',
    example: 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0...'
  })
  accessToken: string;

  @ApiProperty({
    description: 'Refresh token',
    example: 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0...'
  })
  refreshToken: string;
}

export class UserData {
  @ApiProperty({description: 'User ID', example: 1})
  id: number;

  @ApiProperty({description: 'User email', example: 'user@example.com'})
  email: string;

  @ApiProperty({description: 'User first name', example: 'John'})
  firstName: string;

  @ApiProperty({description: 'User last name', example: 'Doe'})
  lastName: string;

  @ApiProperty({description: 'Account creation timestamp', example: '2025-10-31T13:55:58.802Z', required: false})
  createdAt?: Date;
}
