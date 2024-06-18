// import { IsBoolean, IsEmail, IsNotEmpty, IsString } from 'class-validator';
//
//
// export class SignInResponseUserDto {
//   @IsNotEmpty()
//   id: number;
//
//   @IsEmail()
//   @IsNotEmpty()
//   email: string;
//
//   @IsString()
//   @IsNotEmpty()
//   firstName: string;
//
//   @IsString()
//   @IsNotEmpty()
//   lastName: string;
// }
//
// export class ExistingUserDto {
//   @IsNotEmpty()
//   id: number;
//
//   @IsEmail()
//   @IsNotEmpty()
//   email: string;
//
//   @IsString()
//   @IsNotEmpty()
//   password: string;
//
//   @IsString()
//   @IsNotEmpty()
//   firstName: string;
//
//   @IsString()
//   @IsNotEmpty()
//   lastName: string;
//
//   @IsBoolean()
//   @IsNotEmpty()
//   verified: boolean;
//
//   @IsBoolean()
//   @IsNotEmpty()
//   isForgetPassword: boolean;
// }
//
// export class TokenPayloadDto {
//   @IsNotEmpty()
//   id: number;
//
//   @IsEmail()
//   @IsNotEmpty()
//   email: string;
//
//   @IsString()
//   @IsNotEmpty()
//   firstName: string;
//
//   @IsString()
//   @IsNotEmpty()
//   lastName: string;
//
//   @IsBoolean()
//   @IsNotEmpty()
//   verified: boolean;
//
//   @IsBoolean()
//   @IsNotEmpty()
//   isForgetPassword: boolean;
// }
//
// export class SignupResponseUserDto {
//   @IsNotEmpty()
//   id: number;
//
//   @IsEmail()
//   @IsNotEmpty()
//   email: string;
//
//   @IsString()
//   @IsNotEmpty()
//   firstName: string;
//
//   @IsString()
//   @IsNotEmpty()
//   lastName: string;
// }
//
// export class CreatedUserDto {
//   @IsNotEmpty()
//   id: number;
//
//   @IsEmail()
//   @IsNotEmpty()
//   email: string;
//
//   @IsString()
//   @IsNotEmpty()
//   password: string;
//
//   @IsString()
//   @IsNotEmpty()
//   firstName: string;
//
//   @IsString()
//   @IsNotEmpty()
//   lastName: string;
//
//   @IsBoolean()
//   @IsNotEmpty()
//   verified: boolean;
//
//   @IsBoolean()
//   @IsNotEmpty()
//   isForgetPassword: boolean;
// }


import { IsBoolean, IsEmail, IsNotEmpty, IsString } from 'class-validator';

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

export class ExistingUserDto {
  @IsNotEmpty()
  id: number;

  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsString()
  @IsNotEmpty()
  firstName: string;

  @IsString()
  @IsNotEmpty()
  lastName: string;

  @IsBoolean()
  @IsNotEmpty()
  verified: boolean;

  @IsBoolean()
  @IsNotEmpty()
  isForgetPassword: boolean;
}

export class TokenPayloadDto {
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

  @IsBoolean()
  @IsNotEmpty()
  verified: boolean;

  @IsBoolean()
  @IsNotEmpty()
  isForgetPassword: boolean;
}

export class SignupResponseUserDto {
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

export class CreatedUserDto {
  @IsNotEmpty()
  id: number;

  @IsEmail()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsString()
  @IsNotEmpty()
  firstName: string;

  @IsString()
  @IsNotEmpty()
  lastName: string;

  @IsBoolean()
  @IsNotEmpty()
  verified: boolean;

  @IsBoolean()
  @IsNotEmpty()
  isForgetPassword: boolean;
}
