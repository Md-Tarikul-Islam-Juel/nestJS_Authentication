import {MailerService} from '@nestjs-modules/mailer';
import {
    BadRequestException,
    ConflictException, ForbiddenException, HttpException, HttpStatus,
    Injectable, UnauthorizedException,
} from '@nestjs/common';

import {ConfigService} from '@nestjs/config';
import {JwtService} from '@nestjs/jwt';
import * as bcrypt from 'bcrypt';

import * as otpGenerator from 'otp-generator';
import {PrismaService} from 'src/modules/prisma/prisma.service';
import { generateJwtAccessToken, generateJwtRefreshToken } from '../utils/utils';
import {
    ChangePasswordDto,
    ForgetPasswordDto,
    ResendDto,
    SigninDto,
    SignupDto,
    VerificationDto
} from "../dto/authRequest.dto";
import {
    ChangePasswordErrorResponseDto,
    ChangePasswordSuccessResponseDto, RefreshTokenSuccessResponseDto,
    ResendErrorResponseDto,
    ResendSuccessResponseDto,
    SigninSuccessResponseDto, SigninUnauthorizedResponseDto, SigninUserUnverifiedResponseDto,
    SignupSuccessResponseDto,
    SignupUserAlreadyExistResponseDto, VerificationErrorResponseDto, VerificationSuccessResponseDto,
} from '../dto/authRespnse.dto';
import {
    emailSubject,
    failedToChangePassword, oldPasswordIsRequired,
    otpAuthorised, otpEmailSend, otpEmailSendFail,
    otpVerificationFailed,
    signinSuccessful,
    signupSuccessful,
    unauthorized,
    userAlreadyExists,
    verifyYourUser, yourPasswordHasBeenUpdated
} from "../utils/string";


@Injectable()
export class AuthService {
    constructor(
        private readonly prisma: PrismaService,
        private jwtAccessToken: JwtService,
        private jwtRefreshToken: JwtService,
        private config: ConfigService,
        private mailerService: MailerService,
    ) {
    }

    async signup(signupData: SignupDto): Promise<SignupSuccessResponseDto | SignupUserAlreadyExistResponseDto> {
        //Before create new user first here we will check user already exist or not
        const isUserExist = await this.prisma.user.findUnique({
            where: {
                email: signupData.email,
            },
            select: {
                email: true,
            },
        })

        if (isUserExist) {
            throw new ConflictException({message: userAlreadyExists});
        }

        // Hash the user's password for security
        const hashedPassword = await bcrypt.hash(signupData.password, 11);

        // Create a new user in the database
        const user = await this.prisma.user.create({
            data: {
                ...signupData, // Spread the rest of the properties from signupData
                verified: false,
                isForgetPassword: false,
                password: hashedPassword, // replace password
            },
            select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
            },
        });

        await this.sendOtp(signupData.email);

        return {
            success: true,
            message: signupSuccessful,
            data: user,
        };
    }

    async signin(signinData: SigninDto): Promise<SigninSuccessResponseDto | SigninUnauthorizedResponseDto | SigninUserUnverifiedResponseDto> {
        // Find the user by email in the database
        const existingUser = await this.prisma.user.findUnique({
            where: {
                email: signinData.email,
            },
            select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
                password: true,
                verified: true,
            },
        });

        // If the user is not found, throw a UnauthorizedException exception
        if (!existingUser) {
            throw new UnauthorizedException({message: unauthorized});
        }

        if (existingUser.verified === false) {
            throw new ForbiddenException({message: verifyYourUser});
        }

        // Compare the provided password with the hashed password
        const passwordMatch = await bcrypt.compare(
            signinData.password,
            existingUser.password,
        );

        // If passwords don't match, throw a BadRequest exception
        if (!passwordMatch) {
            throw new UnauthorizedException({message: unauthorized});
        }


        if (existingUser.verified === true) {
            // Return the JWT token directly
            const accessToken = generateJwtAccessToken(this.jwtAccessToken, existingUser);
            const refreshToken = generateJwtRefreshToken(this.jwtRefreshToken, existingUser);

            const {
                // eslint-disable-next-line @typescript-eslint/no-unused-vars
                password,
                // eslint-disable-next-line @typescript-eslint/no-unused-vars
                verified,
                ...restUser
            } = existingUser;
            const userWithoutSomeInfo = {...restUser};

            return {
                success: true,
                message: signinSuccessful,
                accessToken: accessToken,
                refreshToken: refreshToken,
                data: {...userWithoutSomeInfo},
            };
        }
    }

    async verificationOtp(
        EmailVerificationByOTPData: VerificationDto,
    ): Promise<VerificationSuccessResponseDto | VerificationErrorResponseDto> {
        // Find the user by email in the database
        // if user not found then no need to send email
        const existingUser = await this.prisma.user.findUnique({
            where: {
                email: EmailVerificationByOTPData.email,
            },
            select: {
                id: true,
                email: true,
                firstName: true,
                lastName: true,
            },
        });

        // If the user is not found, we will not throw a UnauthorizedException exception because security issues
        if (!existingUser) {
            throw new UnauthorizedException({message: otpVerificationFailed});
        }

        //now we will check OTP exist in the database for the particulate user
        const otpRecord = await this.prisma.OTP.findUnique({
            where: {email: EmailVerificationByOTPData.email},
            select: {
                otp: true
            }
        });

        if (otpRecord) {
            //now we will compare the database OTP and user provided OTP
            if (otpRecord.otp.toString() === EmailVerificationByOTPData.otp) {
                //update user is verified
                await this.prisma.user.update({
                    where: {
                        email: EmailVerificationByOTPData.email,
                    },
                    data: {
                        verified: true, // Update the verified field to true
                    },
                });

                // Return the JWT token directly
                const accessToken = generateJwtAccessToken(this.jwtAccessToken, existingUser);
                const refreshToken = generateJwtRefreshToken(this.jwtRefreshToken, existingUser);


                //after update delete the OTP here
                await this.prisma.OTP.delete({
                    where: {email: EmailVerificationByOTPData.email},
                });

                return {
                    success: true,
                    message: otpAuthorised,
                    accessToken: accessToken,
                    refreshToken: refreshToken,
                    data: existingUser,
                };
            } else {
                throw new UnauthorizedException({message: otpVerificationFailed});
            }
        } else {
            throw new UnauthorizedException({message: otpVerificationFailed});
        }
    }

    async resend(ResendOTPData: ResendDto): Promise<ResendSuccessResponseDto | ResendErrorResponseDto> {
        return this.sendOtp(ResendOTPData.email);
    }

    async forgetPassword(
        ForgetPasswordSendEmailForOTPData: ForgetPasswordDto,
    ) {
        const existingUser = await this.prisma.user.findFirst({
            where: {
                email: ForgetPasswordSendEmailForOTPData.email,
            },
            select: {
                email: true
            }
        });

        // If the user is not found
        if (!existingUser) {
            throw new BadRequestException({message: otpEmailSendFail})
        } else {
            //update user is isForgetPassword
            await this.prisma.user.update({
                where: {
                    email: ForgetPasswordSendEmailForOTPData.email,
                },
                data: {
                    isForgetPassword: true, // Update the verified field to true
                },
            });

            return this.sendOtp(ForgetPasswordSendEmailForOTPData.email);
        }
    }

    async ChangePassword(ChangePasswordData: ChangePasswordDto, req: any): Promise<ChangePasswordSuccessResponseDto | ChangePasswordErrorResponseDto> {
        // Find the user by jwt token details in the database
        const existingUser = await this.prisma.user.findUnique({
            where: {
                ...req.user,
            },
            select: {
                isForgetPassword: true,
                verified: true,
                password: true,
            }
        })


        // If the user is not found,
        if (!existingUser) {
            throw new BadRequestException({message: failedToChangePassword});
        }

        if (
            req.user.isForgetPassword === true &&
            existingUser.isForgetPassword === true
        ) {
            //================================
            // this block for Forget password
            //================================
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
                message: yourPasswordHasBeenUpdated,
            };
        } else if (
            req.user.isForgetPassword === false &&
            existingUser.isForgetPassword === false
        ) {
            //================================
            // this block for changed password
            //================================
            if (!ChangePasswordData.oldPassword) {
                throw new BadRequestException({message: oldPasswordIsRequired});
            }

            // Compare the provided password with the hashed password
            const passwordMatch = await bcrypt.compare(
                ChangePasswordData.oldPassword,
                existingUser.password,
            );

            // If passwords don't match,
            if (!passwordMatch) {
                throw new BadRequestException({message: failedToChangePassword});
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
                    message: yourPasswordHasBeenUpdated,
                };
            } else {
                //if user not verified
                throw new ForbiddenException({message: verifyYourUser});

            }
        } else {
            // user is not authorized to change password because user not called forget password api-> verify api
            throw new BadRequestException({message: failedToChangePassword});
        }
    }

    async refreshToken(req:any):Promise<RefreshTokenSuccessResponseDto>{
        try {
            const user = await this.prisma.user.findUnique({
                where: {
                    email: req.user.email,
                },
                select: {
                    id: true,
                    email: true,
                    firstName: true,
                    lastName: true,
                },
            });

            if (!user) {
                throw new HttpException('Invalid Refresh Token', HttpStatus.NOT_FOUND);
            }

            const accessToken = generateJwtAccessToken(this.jwtAccessToken, user);

            return {success: true, accessToken: accessToken};
        } catch (error) {
            throw new HttpException('An error occurred while retrieving user data.', HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
    //-----------------------------------------------------------------------------
    //------------------------------Common function--------------------------------
    //-----------------------------------------------------------------------------
    //OTP generate and email send
    private async sendOtp(email: string): Promise<ResendSuccessResponseDto | ResendErrorResponseDto> {
        // Find the user by email in the database
        // if user not found then no need to send email
        const existingUser = await this.prisma.user.findUnique({
            where: {
                email,
            },
        });

        // If the user is not found, throw a NotFound exception
        if (!existingUser) {
            throw new BadRequestException({message: otpEmailSendFail})
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
        const otpRecord = await this.prisma.OTP.findUnique({
            where: {email},
        });

        if (otpRecord) {
            //delete OTP here
            await this.prisma.OTP.delete({
                where: {email},
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
        await this.mailerService.sendMail({
            to: email,
            from: this.config.get('MAIL_USER'),
            subject: emailSubject,
            text: otp,
        });
        return {
            success: true,
            message: otpEmailSend,
        };
    }
}
