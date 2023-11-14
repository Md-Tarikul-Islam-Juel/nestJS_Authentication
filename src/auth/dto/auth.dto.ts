import * as Joi from 'joi';

//signup
export const signupDto = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
  firstName: Joi.string().optional(),
  lastName: Joi.string().optional(),
});

export interface signupDtoType {
  email: string;
  password: string;
  firstName?: string;
  lastName?: string;
}

//signin
export const signinDto = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required(),
});

export interface signinDtoType {
  email: string;
  password: string;
}

//resend
export const resendDto = Joi.object({
  email: Joi.string().email().required(),
});

export interface resendDtoType {
  email: string;
}

//verification
export const verificationDto = Joi.object({
  email: Joi.string().email().required(),
  otp: Joi.string()
    .regex(/^\d{6}$/)
    .required(),
});

export interface verificationDtoType {
  email: string;
  otp: string;
}

//forget password
export const forgetPasswordDto = Joi.object({
  email: Joi.string().email().required(),
});

export interface forgetPasswordDtoType {
  email: string;
}

//change password
export const changePasswordDto = Joi.object({
  oldPassword: Joi.string().optional(),
  newPassword: Joi.string().required(),
});

export interface changePasswordDtoType {
  oldPassword?: string;
  newPassword: string;
}
