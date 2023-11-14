import { MailerService } from '@nestjs-modules/mailer';
import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';

import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

import * as otpGenerator from 'otp-generator';
import { PrismaService } from 'src/prisma/prisma.service';
import { authDto } from './dto/index';
import { string } from './utils/index';
import { generateJwtToken } from './utils/utils';
@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private jwt: JwtService,
    private config: ConfigService,
    private mailerService: MailerService,
  ) {}

  async signup(signupData: authDto.signupDtoType) {
    // Hash the user's password for security
    const hashedPassword = await bcrypt.hash(signupData.password, 11);

    // Create a new user in the database
    const user = await this.prisma.user.create({
      data: {
        ...signupData, // Spread the rest of the properties from signupData
        verified: false,
        isForgetPassword: false,
        password: hashedPassword, // replace pasword
      },
    });

    await this.sendOtp(signupData.email);

    const {
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      password,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      isForgetPassword,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      createdAt,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      updatedAT,
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      verified,
      ...restUser
    } = user;
    const userWithoutSomeInfo = { ...restUser };

    // Return a success message and the user (without password)
    return {
      success: true,
      message: string.Signup_successfull,
      data: userWithoutSomeInfo,
    };
  }

  async signin(signinData: authDto.signinDtoType) {
    // Find the user by email in the database
    const existingUser = await this.prisma.user.findFirst({
      where: {
        email: signinData.email,
      },
    });

    // If the user is not found, throw a NotFound exception
    if (!existingUser) {
      throw new NotFoundException(string.user_not_found);
    }

    // Compare the provided password with the hashed password
    const passwordMatch = await bcrypt.compare(
      signinData.password,
      existingUser.password,
    );

    // If passwords don't match, throw a BadRequest exception
    if (!passwordMatch) {
      throw new UnauthorizedException(string.Invalid_credentials);
    }

    if (existingUser.verified === true) {
      // Return the JWT token directly
      const token = await generateJwtToken(this.jwt, existingUser);

      const {
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        password,
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        isForgetPassword,
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        createdAt,
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        updatedAT,
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        verified,
        ...restUser
      } = existingUser;
      const userWithoutSomeInfo = { ...restUser };

      return {
        success: true,
        message: string.Signin_successfull,
        token: token,
        data: { ...userWithoutSomeInfo },
      };
    } else {
      throw new ForbiddenException(string.verify_your_user);
    }
  }

  async verificationOtp(
    EmailVerificationByOTPData: authDto.verificationDtoType,
  ) {
    // Find the user by email in the database
    // if user not found then no need to send email
    const existingUser = await this.prisma.user.findFirst({
      where: {
        email: EmailVerificationByOTPData.email,
      },
    });

    // If the user is not found, throw a NotFound exception
    if (!existingUser) {
      throw new NotFoundException(string.user_not_found);
    }

    //now we will check OTP exist in the database for the perticuler user
    const otpRecord = await this.prisma.OTP.findFirst({
      where: { email: EmailVerificationByOTPData.email },
    });

    // console.log(otpRecord.otp);

    if (otpRecord) {
      //now we will comperate the database OTP and user provided OTP
      if (otpRecord.otp.toString() === EmailVerificationByOTPData.otp) {
        //update user is verified
        await this.prisma.user.update({
          where: {
            email: EmailVerificationByOTPData.email, // Specify the user's ID here
          },
          data: {
            verified: true, // Update the verified field to true
          },
        });

        // Return the JWT token directly
        const token = await generateJwtToken(this.jwt, existingUser);

        //after update delete the OTP here
        await this.prisma.OTP.delete({
          where: { email: EmailVerificationByOTPData.email },
        });

        const {
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
          password,
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
          isForgetPassword,
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
          createdAt,
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
          updatedAT,
          // eslint-disable-next-line @typescript-eslint/no-unused-vars
          verified,

          ...restUser
        } = existingUser;
        const userWithoutSomeInfo = { ...restUser };

        return {
          success: true,
          message: 'OTP authorised',
          token: token,
          data: { ...userWithoutSomeInfo },
        };
      }
    } else {
      throw new NotFoundException('otp not found');
    }
  }

  async resend(ResendOTPData: authDto.resendDtoType) {
    //no need try catch here
    return await this.sendOtp(ResendOTPData.email);
  }

  async forgetPassword(
    ForgetPasswordSendEmailForOTPData: authDto.forgetPasswordDtoType,
  ) {
    const existingUser = await this.prisma.user.findFirst({
      where: {
        email: ForgetPasswordSendEmailForOTPData.email,
      },
    });

    // If the user is not found, throw a NotFound exception
    if (!existingUser) {
      throw new NotFoundException(string.user_not_found);
    } else {
      //update user is isForgetPassword
      await this.prisma.user.update({
        where: {
          email: ForgetPasswordSendEmailForOTPData.email, // Specify the user's ID here
        },
        data: {
          isForgetPassword: true, // Update the verified field to true
        },
      });
      //no need try catch here
      return await this.sendOtp(ForgetPasswordSendEmailForOTPData.email);
    }
  }

  async ChangePassword(ChangePasswordData: authDto.changePasswordDtoType, req) {
    // Find the user by jwt token details in the database
    const existingUser = await this.prisma.user.findFirst({
      where: {
        ...req.user,
      },
    });

    // If the user is not found, throw a NotFound exception
    if (!existingUser) {
      throw new NotFoundException(string.user_not_found);
    }
    console.log(existingUser);
    console.log(req);
    if (
      req.user.isForgetPassword === true &&
      existingUser.isForgetPassword === true
    ) {
      // Hash the user's password for security
      const hashedPassword = await bcrypt.hash(
        ChangePasswordData.newPassword,
        11,
      );

      //update user if is verified
      //verified by jwt token details in the database
      await this.prisma.user.update({
        where: {
          ...req.user,
        },
        data: {
          password: hashedPassword, // Update the verified field to true
          isForgetPassword: false,
        },
      });

      return {
        success: true,
        message: 'Your password has been updated',
      };
    } else if (
      req.user.isForgetPassword === false &&
      existingUser.isForgetPassword === false
    ) {
      // Compare the provided password with the hashed password
      if (!ChangePasswordData.oldPassword) {
        throw new ForbiddenException('Old password is required');
      }

      const passwordMatch = await bcrypt.compare(
        ChangePasswordData.oldPassword,
        existingUser.password,
      );

      // If passwords don't match, throw a BadRequest exception
      if (!passwordMatch) {
        throw new BadRequestException(string.Invalid_credentials);
      }

      if (existingUser.verified === true) {
        // Hash the user's password for security
        const hashedPassword = await bcrypt.hash(
          ChangePasswordData.newPassword,
          11,
        );

        //update user if is verified
        //verified by jwt token details in the database
        await this.prisma.user.update({
          where: {
            ...req.user,
          },
          data: {
            password: hashedPassword, // Update the verified field to true
          },
        });

        return {
          success: true,
          message: string.change_password_message,
        };
      } else {
        return {
          success: false,
          message: string.verify_your_user,
        };
      }
    } else {
      throw new UnauthorizedException('You are not allowed to change password');
    }
  }
  //-----------------------------------------------------------------------------
  //-----------------------------------------------------------------------------
  //-----------------------------------------------------------------------------
  //OTP generate and email send
  private async sendOtp(email: any) {
    // Find the user by email in the database
    // if user not found then no need to send email
    const existingUser = await this.prisma.user.findFirst({
      where: {
        email,
      },
    });

    // If the user is not found, throw a NotFound exception
    if (!existingUser) {
      throw new NotFoundException(string.user_not_found);
    }

    const otp = otpGenerator.generate(6, {
      digits: true,
      upperCase: false,
      lowercase: false,
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false,
    });

    // retrieved the OTP record from the database
    const otpRecord = await this.prisma.OTP.findFirst({
      where: { email },
    });

    if (otpRecord) {
      //delete OTP here
      await this.prisma.OTP.delete({
        where: { email },
      });

      // Store OTP in the database using Prisma
      await this.prisma.OTP.create({
        data: {
          email,
          otp,
        },
      });
    } else if (!otpRecord) {
      // Store OTP in the database using Prisma
      await this.prisma.OTP.create({
        data: {
          email,
          otp,
        },
      });
    }

    // Send OTP via email (your email sending logic here)
    const result_after_send_email = await this.mailerService.sendMail({
      to: email,
      from: this.config.get('MAIL_USER'),
      subject: string.EmailSubject,
      text: otp,
    });

    console.log(result_after_send_email);

    return {
      success: true,
      message: string.OTP_EMAIL_SEND,
    };
  }

  async createUser(body: any) {
    const result = await this.prisma.user.create({
      data: {
        ...body, // Spread the rest of the properties from signupData
        verified: true,
        isForgetPassword: false,
        password: 'hashedPassword', // replace pasword
      },
    });

    return result;
  }
}
