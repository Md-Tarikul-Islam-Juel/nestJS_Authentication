import { IsEmail, IsNotEmpty, IsOptional, IsString, Matches } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { emailIsRequired, emailMustBeAValidEmailAddress, otpMustBeA6DigitNumber } from '../utils/string';

// Base class for email validation
export class EmailDto {
  @ApiProperty({ example: 'user@example.com', description: 'The email of the user' })
  @IsEmail({}, { message: emailMustBeAValidEmailAddress })
  @IsNotEmpty({ message: emailIsRequired })
  email: string;
}

// Base class for password validation
export class PasswordDto {
  @ApiProperty({ example: 'password', description: 'The password for the account' })
  @IsString()
  @IsNotEmpty({ message: 'Password is required' })
  password: string;
}

// Base class for name validation (optional)
export class NameDto {
  @ApiProperty({ example: 'John', description: 'The first name of the user', required: false })
  @IsString()
  @IsOptional()
  firstName?: string;

  @ApiProperty({ example: 'Doe', description: 'The last name of the user', required: false })
  @IsString()
  @IsOptional()
  lastName?: string;
}

// Base class for OTP validation
export class OtpDto {
  @ApiProperty({
    example: '123456',
    description: 'A six-digit OTP (One-Time Password)',
  })
  @Matches(/^\d{6}$/, {
    message: otpMustBeA6DigitNumber,
  })
  otp: string;
}

// Base class for response DTOs
export class BaseResponseDto {
  @ApiProperty({ description: 'Indicates if the operation was successful', example: true })
  success: boolean;

  @ApiProperty({ description: 'Message indicating the result of the operation', example: 'Operation successful' })
  message: string;
}

// Tokens class
export class Tokens {
  @ApiProperty({
    description: 'Access token',
    example: 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..i0c8AGVUphy1lsLv.0xf99dwwa3q9xcb8jC_2y_NrsDnRkNUt7Km3EZakukw7L5mQEfij3SkkfqfAvdzq39Jg7vY78LRmwICrpbhc2Yt21ZXueKgKS3Qh1kTsUy4Za7xS2dIlRYWuxYwx2S9p5lvLItUExTobv4y62_SG-bYsCZwmLJwHbF10IWll2rfakf7Mr8tLsiyTy8QxvQNjMKFjM8PNavSbUIoY2Yzai_9Cj8x3ppcpuTdvQ4M0uY9ePQEOyUiqhgq8brsDP_hu6L-WOeP74sOrWbr4dV5FrK0Zzq_hitNGddRoZuA0JrNWRISlkaGlivozILnLmXwcNSFjB8hszoQpL0T46dtOVM4wM1pz0iLb_INxnN6Mxkfcdz_izk8hC0wPxlGF1tLa9xqMg0SbPzGjTWk.q2CJhV1zSYun1EJmrbrW3A',
  })
  accessToken: string;

  @ApiProperty({
    description: 'Refresh token',
    example: 'eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..t0P-PayYxsYfcTDe.fMFodBF2Q8_nOCxt_Wa3mDtqwdQ53zrB86c4WMFz7hBbxpTRUy41hFL5hsdR7rlKAiHcbiePJGQweP2N01mMpOop5hqmQSjvQXXTfHP-wxwxx_7l_UBKcDmQ4ppI6oHJQwA9yCBZ72hykjbsxmwMdXqpX5-ApUQdzof8RwzW9P8oIWtXiFNmJfhkiWpZLSXBE-_fmpwr0lV3uvSZlM46quKhURifACv8B4yx5UGK2oB2hIdGEheunUdF0cpP4CMmI3f0QoBFJBTrkJpiMjj38XcwrnBF6cXoI3_60czgWelcgv1XcmqrjLK2iknsgbpb7GBxeHK24poqxfXiqa-eLxW2KUOJEkoifj0lqbL4Vgo6b76XasayOTb0KZwOb44_zyPnoANbl4Q7L34._eTs2TuRAlIIRtXUHYEBow',
  })
  refreshToken: string;
}

// User data class
export class UserData {
  @ApiProperty({ description: 'User ID', example: 1 })
  id: number;

  @ApiProperty({ description: 'User email', example: 'user@example.com' })
  email: string;

  @ApiProperty({ description: 'User first name', example: 'John' })
  firstName: string;

  @ApiProperty({ description: 'User last name', example: 'Doe' })
  lastName: string;
}
