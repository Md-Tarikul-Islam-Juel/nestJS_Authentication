import {ApiProperty} from "@nestjs/swagger";
import {
    failedToChangePassword, otpAuthorised,
    otpEmailSend, otpEmailSendFail,
    otpVerificationFailed,
    signinSuccessful,
    signupSuccessful,
    unauthorized,
    userAlreadyExists,
    verifyYourUser, yourPasswordHasBeenUpdated
} from "../utils/string";


// =================================================================
//----------------------------SIGN UP-------------------------------
// =================================================================
export class SignupResponseDataDto {
    @ApiProperty({description: "User ID", example: 19})
    id: number;

    @ApiProperty({description: "Email address of the user", example: "david@gmail.com"})
    email: string;

    @ApiProperty({description: "First name of the user", example: "david"})
    firstName: string;

    @ApiProperty({description: "Last name of the user", example: "beckham"})
    lastName: string;
}

export class SignupSuccessResponseDto {
    @ApiProperty({description: "Indicates if the signup was successful", example: true})
    success: boolean;

    @ApiProperty({description: "Message indicating the result of the signup process", example: `${signupSuccessful}`})
    message: string;

    @ApiProperty({description: "Data of the signed-up user", type: SignupResponseDataDto})
    data: SignupResponseDataDto;
}

export class SignupUserAlreadyExistResponseDto {
    @ApiProperty({description: "Indicates if the operation was unsuccessful", example: false})
    success: boolean;

    @ApiProperty({description: "Message indicating the reason for failure", example: userAlreadyExists})
    message: string;
}


// =================================================================
//----------------------------SIGN IN-------------------------------
// =================================================================
export class SigninUserData {
    @ApiProperty({description: 'User ID', example: 1})
    id: number;

    @ApiProperty({description: 'User email', example: 'user@example.com'})
    email: string;

    @ApiProperty({description: 'User first name', example: 'John'})
    firstName: string;

    @ApiProperty({description: 'User last name', example: 'Doe'})
    lastName: string;
}

export class SigninSuccessResponseDto {
    @ApiProperty({description: 'Indicates if the signin was successful', example: true})
    success: boolean;

    @ApiProperty({description: 'Message indicating the result of the signin process', example: signinSuccessful})
    message: string;

    @ApiProperty({description: 'Data of the signed-in user', type: SigninUserData})
    data: SigninUserData;

    @ApiProperty({description: 'JWT token for authentication', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'})
    token: string;
}

export class SigninUnauthorizedResponseDto {
    @ApiProperty({description: 'Indicates if the signin was unsuccessful', example: false})
    success: boolean;

    @ApiProperty({description: 'Message indicating unauthorized access', example: unauthorized})
    message: string;
}

export class SigninUserUnverifiedResponseDto {
    @ApiProperty({description: 'Indicates if the signin was unsuccessful', example: false})
    success: boolean;

    @ApiProperty({description: 'Message indicating Unverified user', example: verifyYourUser})
    message: string;
}

// =================================================================
//-------------------------Verification-----------------------------
// =================================================================
export class VerificationUserData {
    @ApiProperty({description: 'User ID', example: 2})
    id: number;

    @ApiProperty({description: 'User email', example: 'user@example.com'})
    email: string;

    @ApiProperty({description: 'User first name', example: 'user'})
    firstName: string;

    @ApiProperty({description: 'User last name', example: 'user'})
    lastName: string;
}

export class VerificationSuccessResponseDto {
    @ApiProperty({description: 'Indicates if the OTP verification was successful', example: true})
    success: boolean;

    @ApiProperty({
        description: 'Message indicating the result of the OTP verification process',
        example: otpAuthorised
    })
    message: string;

    @ApiProperty({description: 'JWT token for authentication', example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...'})
    token: string;

    @ApiProperty({description: 'Data of the verified user', type: VerificationUserData})
    data: VerificationUserData;
}

export class VerificationErrorResponseDto {
    @ApiProperty({description: 'Indicates if the OTP verification was unsuccessful', example: false})
    success: boolean;

    @ApiProperty({
        description: 'Message indicating the reason for OTP verification failure',
        example: otpVerificationFailed
    })
    message: string;
}


// =================================================================
//-----------------------------Resend-------------------------------
// =================================================================
export class ResendSuccessResponseDto {
    @ApiProperty({description: 'Indicates if the OTP email was sent successfully', example: true})
    success: boolean;

    @ApiProperty({
        description: 'Message indicating the result of the OTP email sending process',
        example: otpEmailSend
    })
    message: string;
}

export class ResendErrorResponseDto {
    @ApiProperty({description: 'Indicates if the OTP email sending failed', example: false})
    success: boolean;

    @ApiProperty({
        description: 'Message indicating the reason for OTP email sending failure',
        example: otpEmailSendFail
    })
    message: string;
}

// =================================================================
//------------------------Forget Password---------------------------
// =================================================================
export class ForgetPasswordSuccessResponseDto {
    @ApiProperty({description: 'Indicates if the OTP email was sent successfully', example: true})
    success: boolean;

    @ApiProperty({
        description: 'Message indicating the result of the OTP email sending process',
        example: otpEmailSend
    })
    message: string;
}

export class ForgetPasswordErrorResponseDto {
    @ApiProperty({description: 'Indicates if the OTP email sending failed', example: false})
    success: boolean;

    @ApiProperty({
        description: 'Message indicating the reason for OTP email sending failure',
        example: otpEmailSendFail
    })
    message: string;
}

// =================================================================
//------------------------Change Password---------------------------
// =================================================================
export class ChangePasswordSuccessResponseDto {
    @ApiProperty({description: 'Indicates if the password change was successful', example: true})
    success: boolean;

    @ApiProperty({
        description: 'Message indicating the result of the password change',
        example: yourPasswordHasBeenUpdated
    })
    message: string;
}

export class ChangePasswordErrorResponseDto {
    @ApiProperty({description: 'Indicates if the password change was unsuccessful', example: false})
    success: boolean;

    @ApiProperty({
        description: 'Error message indicating the reason for the password change failure',
        example: failedToChangePassword
    })
    message: string;
}

export class ChangePasswordUnverifiedResponseDto {
    @ApiProperty({description: 'Indicates if the signin was unsuccessful', example: false})
    success: boolean;

    @ApiProperty({description: 'Message indicating Unverified user', example: verifyYourUser})
    message: string;
}