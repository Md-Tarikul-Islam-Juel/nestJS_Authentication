import { IsBoolean, IsEmail, IsIn, IsNotEmpty, IsOptional, IsString, Matches } from 'class-validator';
import {ApiProperty} from "@nestjs/swagger";
import {
    emailIsRequired,
    emailMustBeAValidEmailAddress, newPasswordIsRequired,
    otpMustBeA6DigitNumber,
    passwordIsRequired
} from "../utils/string";

// =================================================================
//----------------------------SIGN UP-------------------------------
// =================================================================
export class SignupDto {
    @ApiProperty({example: 'user@example.com', description: 'The email of the user'})
    @IsEmail({}, {message: emailMustBeAValidEmailAddress})
    @IsNotEmpty({message: emailIsRequired})
    email: string;

    @ApiProperty({example: 'password', description: 'The password for the account'})
    @IsString()
    @IsNotEmpty({message: passwordIsRequired})
    password: string;

    @ApiProperty({example: 'John', description: 'The first name of the user', required: false})
    @IsString()
    @IsOptional()
    firstName?: string;

    @ApiProperty({example: 'Doe', description: 'The last name of the user', required: false})
    @IsString()
    @IsOptional()
    lastName?: string;
}

// =================================================================
//----------------------------SIGN IN-------------------------------
// =================================================================
export class SigninDto {
    @ApiProperty({example: 'user@example.com', description: 'The email of the user'})
    @IsEmail({}, {message: emailMustBeAValidEmailAddress})
    @IsNotEmpty({message: emailIsRequired})
    email: string;

    @ApiProperty({example: 'password', description: 'The password for the account'})
    @IsString()
    @IsNotEmpty({message: passwordIsRequired})
    password: string;
}

export class OAuthDto {
    @ApiProperty({ example: 'example@gmail.com', description: 'The email address of the user' })
    @IsEmail({}, { message: 'Email must be a valid email address' })
    @IsNotEmpty({ message: 'Email is required' })
    email: string;

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
//-----------------------------Resend-------------------------------
// =================================================================
export class ResendDto {
    @ApiProperty({example: 'user@example.com', description: 'The email of the user'})
    @IsEmail({}, {message: emailMustBeAValidEmailAddress})
    @IsNotEmpty({message: emailIsRequired})
    email: string;
}

// =================================================================
//-------------------------Verification-----------------------------
// =================================================================
export class VerificationDto {
    @ApiProperty({example: 'user@example.com', description: 'The email of the user'})
    @IsEmail({}, {message: emailMustBeAValidEmailAddress})
    @IsNotEmpty({message: emailIsRequired})
    email: string;

    @ApiProperty({
        example: '123456',
        description: 'A six-digit OTP (One-Time Password)',
    })
    @Matches(/^\d{6}$/, {
        message: otpMustBeA6DigitNumber
    })
    otp: string;
}

// =================================================================
//------------------------Forget Password---------------------------
// =================================================================
export class ForgetPasswordDto {
    @ApiProperty({example: 'user@example.com', description: 'The email of the user'})
    @IsEmail({}, {message: emailMustBeAValidEmailAddress})
    @IsNotEmpty({message: emailIsRequired})
    email: string;
}

// =================================================================
//------------------------Change Password---------------------------
// =================================================================
export class ChangePasswordDto {
    @ApiProperty({
        example: 'oldPassword123',
        description: 'The old password (if changing)'
    })
    @IsString()
    @IsOptional()
    oldPassword?: string;

    @ApiProperty({
        example: 'newPassword123',
        description: 'The new password'
    })
    @IsString()
    @IsNotEmpty({message: newPasswordIsRequired})
    newPassword: string;
}