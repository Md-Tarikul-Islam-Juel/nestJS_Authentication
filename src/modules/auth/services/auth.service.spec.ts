import { AuthService } from './auth.service';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../../prisma/prisma.service';
import {
  BadRequestException, ConflictException, ForbiddenException, HttpException,
  InternalServerErrorException,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import {
  emailSubject,
  failedToSendOTPEmail,
  otpAuthorised,
  otpEmailSend, otpEmailSendFail,
  otpVerificationFailed,
  signinSuccessful, signupSuccessful, sucessfullyGenerateNewTokens,
  unauthorized, userNotFound,
  verifyYourUser, yourPasswordHasBeenUpdated,
} from '../utils/string';
import { JwtService } from '@nestjs/jwt';
import { MailerService } from '@nestjs-modules/mailer';
import * as bcrypt from 'bcrypt';
import {
  ChangePasswordDto,
  ForgetPasswordDto,
  OAuthDto,
  ResendDto,
  SigninDto,
  SignupDto,
  VerificationDto,
} from '../dto/authRequest.dto';
import { CompactEncrypt } from 'jose';
import { CreatedUserDto, ExistingUserDto, SignInResponseUserDto, TokenPayloadDto } from '../dto/auth.internal.dto';
import { Tokens } from '../dto/auth.base.dto';
import { SigninSuccessResponseDto } from '../dto/authRespnse.dto';

// Mocking the 'bcrypt' module
jest.mock('bcrypt', () => ({
  hash: jest.fn(),
  compare: jest.fn(),
  compareSync: jest.fn(),
}));

describe('AuthService', () => {
  let authService: AuthService;
  let configService: ConfigService;
  let prismaService: PrismaService;
  let jwtService: JwtService;
  let mailerService: MailerService;
  let logger: { error: jest.Mock };

  beforeEach(() => {
    // Mocking the ConfigService to return specific configuration values based on the key
    configService = {
      get: jest.fn((key: string) => {
        switch (key) {
          case 'BCRYPT_SALT_ROUNDS':
            return '10';
          case 'OTP_EXPIRE_TIME':
            return '10';
          case 'OTP_SENDER_MAIL':
            return 'noreply@example.com';
          case 'JWT_ACCESS_TOKEN_SECRET':
            return 'access-secret';
          case 'JWT_REFRESH_TOKEN_SECRET':
            return 'refresh-secret';
          case 'JWT_ACCESS_TOKEN_EXPIRATION':
            return '3600s';
          case 'JWT_REFRESH_TOKEN_EXPIRATION':
            return '86400s';
          default:
            return null;
        }
      }),
    } as any;

    // Mocking the logger to provide a custom implementation for the error method
    logger = { error: jest.fn() };

    // Mocking the PrismaService to provide custom implementations for various methods
    prismaService = {
      OTP: {
        findUnique: jest.fn(),
        upsert: jest.fn(),
        delete: jest.fn(),
      },
      user: {
        findUnique: jest.fn(),
        create: jest.fn(),
        update: jest.fn(),
      },
    } as any;

    // Mocking the MailerService to provide a custom implementation for the sendMail method
    mailerService = {
      sendMail: jest.fn(),
    } as any;

    // Mocking the JwtService to provide a custom implementation for the sign method
    jwtService = {
      sign: jest.fn(),
    } as any;

    // Creating an instance of AuthService with the mocked dependencies
    authService = new AuthService(
      prismaService, // PrismaService
      jwtService, // JwtService for access token
      jwtService, // JwtService for refresh token
      configService, // ConfigService
      mailerService, // MailerService
      logger as any, // LoggerService
    );

    // Setting a mock value for the otpSenderMail property in AuthService
    authService['otpSenderMail'] = 'noreply@example.com';

    // Mocking console.error to prevent actual console errors during tests
    jest.spyOn(console, 'error').mockImplementation(() => {
    });
  });

  //-----------------------------------------------------------------------------
  //---------------------------Main method test----------------------------------
  //-----------------------------------------------------------------------------
  describe('signup', () => {
    const signupData: SignupDto = {
      email: 'new@example.com',
      password: 'password',
    };

    it('should throw ConflictException if user already exists', async () => {
      const existUser: ExistingUserDto = {
        id: 1,
        email: 'existing@example.com',
        password: 'hashedPassword',
        firstName: 'John',
        lastName: 'Doe',
        verified: true,
        isForgetPassword: false,
      };

      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(existUser);

      await expect(authService.signup(signupData)).rejects.toThrowError(ConflictException);

    });

    it('should create a new user and send OTP', async () => {
      const hashedPassword = await bcrypt.hash(signupData.password, authService['saltRounds']);
      const createdUser: CreatedUserDto = {
        id: 2,
        email: 'new@example.com',
        password: hashedPassword,
        firstName: 'John',
        lastName: 'Doe',
        verified: false,
        isForgetPassword: false,
      };

      const sanitizedUserDataForResponse = {
        id: 2,
        email: 'new@example.com',
        firstName: 'John',
        lastName: 'Doe',
      };

      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(null);
      jest.spyOn(authService, 'createUser').mockResolvedValue(createdUser);
      jest.spyOn(authService, 'sendOtp').mockResolvedValue({ success: true, message: otpEmailSend });
      jest.spyOn(authService, 'removeSensitiveData').mockReturnValue(sanitizedUserDataForResponse);

      const result = await authService.signup(signupData);

      expect(result.success).toBe(true);
      expect(result.message).toContain(`${signupSuccessful} and please ${verifyYourUser}`);
      if ('data' in result) {
        expect(result.data).toEqual({
          user: sanitizedUserDataForResponse,
        });
      }
      expect(authService.sendOtp).toHaveBeenCalledWith('new@example.com');
    });
  });

  describe('signin', () => {
    it('should throw UnauthorizedException if user does not exist', async () => {
      const signinData: SigninDto = {
        email: 'nonexistent@example.com',
        password: 'password',
      };

      // Mock the findUserByEmail method to return null, simulating a non-existent user
      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(null);

      // Verify that the signin method throws an UnauthorizedException when the user does not exist
      await expect(authService.signin(signinData)).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if password does not match', async () => {
      const signinData: SigninDto = {
        email: 'user@example.com',
        password: 'wrongpassword',
      };

      // Mock an existing user with a hashed password
      const existingUser: ExistingUserDto = {
        id: 1,
        email: 'user@example.com',
        password: 'hashedPassword',
        firstName: 'John',
        lastName: 'Doe',
        verified: true,
        isForgetPassword: false,
      };


      // Mock the findUserByEmail method to return the existing user
      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(existingUser);

      // Mock the authenticateUser method to simulate password mismatch
      jest.spyOn(authService, 'authenticateUser').mockImplementation((user, password) => {
        if (!bcrypt.compareSync(password, user.password)) {
          throw new UnauthorizedException({ message: unauthorized });
        }
      });

      // Verify that the signin method throws an UnauthorizedException when the password does not match
      await expect(authService.signin(signinData)).rejects.toThrow(UnauthorizedException);
    });

    it('should throw ForbiddenException if user is not verified', async () => {
      const signinData: SigninDto = {
        email: 'user@example.com',
        password: 'password',
      };

      // Mock an existing user who is not verified
      const existingUser: ExistingUserDto = {
        id: 1,
        email: 'user@example.com',
        password: 'hashedPassword',
        firstName: 'John',
        lastName: 'Doe',
        verified: false,
        isForgetPassword: false,
      };

      // Mock the findUserByEmail method to return the existing user
      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(existingUser);

      // Mock the authenticateUser method to simulate user not verified
      jest.spyOn(authService, 'authenticateUser').mockImplementation((user, password) => {
        if (!user.verified) {
          throw new ForbiddenException({ message: verifyYourUser });
        }
      });

      // Verify that the signin method throws a ForbiddenException when the user is not verified
      await expect(authService.signin(signinData)).rejects.toThrow(ForbiddenException);
    });

    it('should successfully sign in user and return tokens', async () => {
      const signinData: SigninDto = {
        email: 'user@example.com',
        password: 'password',
      };

      // Mock an existing user who is verified
      const existingUser: ExistingUserDto = {
        id: 1,
        email: 'user@example.com',
        password: 'hashedPassword',
        firstName: 'John',
        lastName: 'Doe',
        verified: true,
        isForgetPassword: false,
      };

      // Prepare the user object without sensitive data for token generation
      const sanitizedUserDataForToken: TokenPayloadDto = {
        id: 1,
        email: 'user@example.com',
        firstName: 'John',
        lastName: 'Doe',
        isForgetPassword: existingUser.isForgetPassword,
        verified: existingUser.verified,
      };

      // Prepare the user object without sensitive data for the response
      const sanitizedUserDataForResponse: SignInResponseUserDto = {
        id: 1,
        email: 'user@example.com',
        firstName: 'John',
        lastName: 'Doe',
      };

      // Mock the tokens
      const token: Tokens = {
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
      };

      // Expected response structure
      const expectedResponse = {
        success: true,
        message: signinSuccessful,
        tokens: token,
        data: { user: sanitizedUserDataForResponse },
      };

      // Mock the necessary methods
      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(existingUser);
      jest.spyOn(authService, 'authenticateUser').mockImplementation(() => {
      });
      jest.spyOn(authService, 'updateForgotPasswordStatus').mockResolvedValue(undefined);
      jest.spyOn(authService, 'removeSensitiveData').mockImplementation((user, fields) => {
        const filteredUser = { ...user };
        fields.forEach(field => {
          delete filteredUser[field];
        });
        return filteredUser;
      });
      jest.spyOn(authService, 'generateTokens').mockResolvedValue(token);
      jest.spyOn(authService, 'buildSigninResponse').mockReturnValue(expectedResponse);

      const result = await authService.signin(signinData);

      // Verify the results
      expect(result).toEqual(expectedResponse);
      expect(authService.updateForgotPasswordStatus).toHaveBeenCalledWith(existingUser.email, false);
      expect(authService.removeSensitiveData).toHaveBeenCalledWith(existingUser, ['password']);
      expect(authService.removeSensitiveData).toHaveBeenCalledWith(existingUser, ['password', 'verified', 'isForgetPassword']);
      expect(authService.generateTokens).toHaveBeenCalledWith(sanitizedUserDataForToken);
      expect(authService.buildSigninResponse).toHaveBeenCalledWith(sanitizedUserDataForResponse, token, signinSuccessful);
    });
  });

  describe('oAuthSignin', () => {
    it('should create a new user if not existing and return tokens', async () => {
      const oAuthSigninData: OAuthDto = {
        email: 'newuser@example.com',
        firstName: 'John',
        lastName: 'Doe',
        loginSource: 'google',
      };

      // Mock the generated password
      const generatedPassword = 'randomPassword123';
      jest.spyOn(authService, 'randomPasswordGenerator').mockReturnValue(generatedPassword);
      const hashedPassword = await bcrypt.hash(generatedPassword, authService['saltRounds']);

      // Mock the created user object
      const CreatedUserDto: ExistingUserDto = {
        id: 1,
        email: 'newuser@example.com',
        firstName: 'John',
        lastName: 'Doe',
        verified: true,
        isForgetPassword: false,
        password: hashedPassword,
      };

      // Mock the user object without sensitive data for token generation
      const sanitizedUserDataForToken: TokenPayloadDto = {
        id: 1,
        email: 'newuser@example.com',
        firstName: 'John',
        lastName: 'Doe',
        verified: true,
        isForgetPassword: false,
      };

      // Mock the user object without sensitive data for response
      const sanitizedUserDataForResponse: SignInResponseUserDto = {
        id: 1,
        email: 'newuser@example.com',
        firstName: 'John',
        lastName: 'Doe',
      };

      // Mock the generated tokens
      const token: Tokens = {
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
      };

      // Expected response structure
      const expectedResponse: SigninSuccessResponseDto = {
        success: true,
        message: signinSuccessful,
        tokens: token,
        data: { user: sanitizedUserDataForResponse },
      };

      // Mock the necessary methods
      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(null);
      jest.spyOn(authService, 'createUser').mockResolvedValue(CreatedUserDto);
      jest.spyOn(authService, 'removeSensitiveData').mockImplementation((user, fields) => {
        const filteredUser = { ...user };
        fields.forEach(field => {
          delete filteredUser[field];
        });
        return filteredUser;
      });
      jest.spyOn(authService, 'generateTokens').mockResolvedValue(token);
      jest.spyOn(authService, 'buildSigninResponse').mockReturnValue(expectedResponse);

      const result = await authService.oAuthSignin(oAuthSigninData);

      expect(result).toEqual(expectedResponse);
      expect(authService.findUserByEmail).toHaveBeenCalledWith(oAuthSigninData.email);
      expect(authService.createUser).toHaveBeenCalledWith(
        oAuthSigninData,
        hashedPassword,
        oAuthSigninData.loginSource,
        true,
      );
      expect(authService.removeSensitiveData).toHaveBeenCalledWith(CreatedUserDto, ['password']);
      expect(authService.removeSensitiveData).toHaveBeenCalledWith(CreatedUserDto, ['password', 'verified', 'isForgetPassword']);
      expect(authService.generateTokens).toHaveBeenCalledWith(sanitizedUserDataForToken);
      expect(authService.buildSigninResponse).toHaveBeenCalledWith(sanitizedUserDataForResponse, token, signinSuccessful);
    });

    it('should return tokens for existing user', async () => {
      const oAuthSigninData: OAuthDto = {
        email: 'existinguser@example.com',
        loginSource: 'google',
        firstName: 'John',
        lastName: 'Doe',
      };

      // Mock an existing user
      const existingUser: ExistingUserDto = {
        id: 1,
        email: 'existinguser@example.com',
        firstName: 'John',
        lastName: 'Doe',
        verified: true,
        isForgetPassword: false,
        password: 'hashedPassword',
      };

      // Mock the user object without sensitive data for token generation
      const sanitizedUserDataForToken: TokenPayloadDto = {
        id: 1,
        email: 'existinguser@example.com',
        firstName: 'John',
        lastName: 'Doe',
        verified: true,
        isForgetPassword: false,
      };

      // Mock the user object without sensitive data for response
      const sanitizedUserDataForResponse: SignInResponseUserDto = {
        id: 1,
        email: 'existinguser@example.com',
        firstName: 'John',
        lastName: 'Doe',
      };

      // Mock the generated tokens
      const token: Tokens = {
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
      };

      // Expected response structure
      const expectedResponse: SigninSuccessResponseDto = {
        success: true,
        message: signinSuccessful,
        tokens: token,
        data: { user: sanitizedUserDataForResponse },
      };

      // Mock the necessary methods
      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(existingUser);
      jest.spyOn(authService, 'removeSensitiveData').mockImplementation((user, fields) => {
        const filteredUser = { ...user };
        fields.forEach(field => {
          delete filteredUser[field];
        });
        return filteredUser;
      });
      jest.spyOn(authService, 'generateTokens').mockResolvedValue(token);
      jest.spyOn(authService, 'buildSigninResponse').mockReturnValue(expectedResponse);

      const result = await authService.oAuthSignin(oAuthSigninData);

      expect(result).toEqual(expectedResponse);
      expect(authService.findUserByEmail).toHaveBeenCalledWith(oAuthSigninData.email);
      expect(authService.removeSensitiveData).toHaveBeenCalledWith(existingUser, ['password']);
      expect(authService.removeSensitiveData).toHaveBeenCalledWith(existingUser, ['password', 'verified', 'isForgetPassword']);
      expect(authService.generateTokens).toHaveBeenCalledWith(sanitizedUserDataForToken);
      expect(authService.buildSigninResponse).toHaveBeenCalledWith(sanitizedUserDataForResponse, token, signinSuccessful);
    });
  });

  describe('verificationOtp', () => {
    it('should successfully verify OTP, update user verification status, delete OTP, and return tokens', async () => {
      const verificationData: VerificationDto = {
        email: 'test@example.com',
        otp: '123456',
      };

      const existingUser: ExistingUserDto = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        verified: false,
        isForgetPassword: false,
        password: 'hashedPassword',
      };

      const updatedUser: ExistingUserDto = {
        ...existingUser,
        verified: true,
      };

      const sanitizedUserDataForToken: TokenPayloadDto = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        verified: true,
        isForgetPassword: false,
      };

      const sanitizedUserDataForResponse: SignInResponseUserDto = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
      };

      const token: Tokens = {
        accessToken: 'access-token',
        refreshToken: 'refresh-token',
      };

      const expectedResponse: SigninSuccessResponseDto = {
        success: true,
        message: otpAuthorised,
        tokens: token,
        data: { user: sanitizedUserDataForResponse },
      };

      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(existingUser);
      jest.spyOn(authService, 'verifyUserAndOtp').mockResolvedValue(undefined);
      jest.spyOn(authService, 'updateUserVerificationStatus').mockImplementation(async (email, verified) => {
        existingUser.verified = verified;
      });
      jest.spyOn(authService, 'deleteOtp').mockResolvedValue(undefined);
      jest.spyOn(authService, 'removeSensitiveData').mockImplementation((user, fields) => {
        const filteredUser = { ...user };
        fields.forEach(field => {
          delete filteredUser[field];
        });
        return filteredUser;
      });
      jest.spyOn(authService, 'generateTokens').mockResolvedValue(token);
      jest.spyOn(authService, 'buildSigninResponse').mockReturnValue(expectedResponse);

      const result = await authService.verificationOtp(verificationData);

      expect(result).toEqual(expectedResponse);
      expect(authService.findUserByEmail).toHaveBeenCalledWith(verificationData.email);
      expect(authService.verifyUserAndOtp).toHaveBeenCalledWith(existingUser, verificationData.otp);
      expect(authService.updateUserVerificationStatus).toHaveBeenCalledWith(existingUser.email, true);
      expect(authService.deleteOtp).toHaveBeenCalledWith(verificationData.email);
      expect(authService.removeSensitiveData).toHaveBeenCalledWith(updatedUser, ['password']);
      expect(authService.generateTokens).toHaveBeenCalledWith(sanitizedUserDataForToken);
      expect(authService.removeSensitiveData).toHaveBeenCalledWith(updatedUser, ['password', 'verified', 'isForgetPassword']);
      expect(authService.buildSigninResponse).toHaveBeenCalledWith(sanitizedUserDataForResponse, token, otpAuthorised);
    });

    it('should throw an error if the user does not exist', async () => {
      const verificationData: VerificationDto = {
        email: 'nonexistent@example.com',
        otp: '123456',
      };

      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(null);

      await expect(authService.verificationOtp(verificationData)).rejects.toThrow(NotFoundException);
      expect(authService.findUserByEmail).toHaveBeenCalledWith(verificationData.email);
    });

    it('should throw an error if OTP verification fails', async () => {
      const verificationData: VerificationDto = {
        email: 'test@example.com',
        otp: '123456',
      };

      const existingUser: ExistingUserDto = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        verified: false,
        isForgetPassword: false,
        password: 'hashedPassword',
      };

      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(existingUser);
      jest.spyOn(authService, 'verifyUserAndOtp').mockImplementation(() => {
        throw new UnauthorizedException('OTP verification failed');
      });

      // Act & Assert
      await expect(authService.verificationOtp(verificationData)).rejects.toThrow(UnauthorizedException);
      expect(authService.findUserByEmail).toHaveBeenCalledWith(verificationData.email);
      expect(authService.verifyUserAndOtp).toHaveBeenCalledWith(existingUser, verificationData.otp);
    });
  });

  describe('resend', () => {
    it('should call sendOtp with the correct email and return the response', async () => {
      const resendOTPData: ResendDto = { email: 'test@example.com' };
      const sendOtpResponse = { success: true, message: 'OTP sent' };

      jest.spyOn(authService, 'sendOtp').mockResolvedValue(sendOtpResponse);

      const result = await authService.resend(resendOTPData);

      expect(authService.sendOtp).toHaveBeenCalledWith(resendOTPData.email);
      expect(result).toEqual(sendOtpResponse);
    });

    it('should handle errors from sendOtp correctly', async () => {
      const resendOTPData: ResendDto = { email: 'test@example.com' };
      const sendOtpError = new Error('Failed to send OTP');

      jest.spyOn(authService, 'sendOtp').mockRejectedValue(sendOtpError);

      await expect(authService.resend(resendOTPData)).rejects.toThrow(sendOtpError);
      expect(authService.sendOtp).toHaveBeenCalledWith(resendOTPData.email);
    });
  });

  describe('forgetPassword', () => {
    it('should throw BadRequestException if user does not exist', async () => {
      const forgetData: ForgetPasswordDto = { email: 'nonexistent@example.com' };

      // Mock findUserByEmail to return null, simulating that the user does not exist
      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(null);

      // Mock verifyUserExist to call the callback function when user is null
      jest.spyOn(authService, 'verifyUserExist').mockImplementation((user, callback, message) => {
        if (!user) {
          callback();
        }
      });

      // Execute the method and verify the behavior
      await expect(authService.forgetPassword(forgetData)).rejects.toThrow(BadRequestException);
      expect(authService.findUserByEmail).toHaveBeenCalledWith(forgetData.email);
      expect(authService.verifyUserExist).toHaveBeenCalledWith(null, expect.any(Function), otpEmailSendFail);
    });

    it('should update forget password field and send OTP if user exists', async () => {
      const forgetData: ForgetPasswordDto = { email: 'test@example.com' };
      const existingUser: ExistingUserDto = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        verified: true,
        isForgetPassword: false,
        password: 'hashedPassword',
      };
      const sendOtpResponse = { success: true, message: 'OTP sent' };

      // Mock findUserByEmail to return an existing user
      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(existingUser);

      // Mock verifyUserExist to do nothing when user exists
      jest.spyOn(authService, 'verifyUserExist').mockImplementation((user, callback, message) => {
        if (!user) {
          callback();
        }
      });

      // Mock updateForgetPasswordField to return undefined (resolved)
      jest.spyOn(authService, 'updateForgotPasswordStatus').mockResolvedValue(undefined);

      // Mock sendOtp to return a success response
      jest.spyOn(authService, 'sendOtp').mockResolvedValue(sendOtpResponse);

      const result = await authService.forgetPassword(forgetData);

      expect(authService.findUserByEmail).toHaveBeenCalledWith(forgetData.email);
      expect(authService.verifyUserExist).toHaveBeenCalledWith(existingUser, expect.any(Function), otpEmailSendFail);
      expect(authService.updateForgotPasswordStatus).toHaveBeenCalledWith(existingUser.email, true);
      expect(authService.sendOtp).toHaveBeenCalledWith(existingUser.email);
      expect(result).toEqual(sendOtpResponse);
    });

    it('should handle errors from sendOtp correctly', async () => {
      const forgetData: ForgetPasswordDto = { email: 'test@example.com' };
      const existingUser: ExistingUserDto = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        verified: true,
        isForgetPassword: false,
        password: 'hashedPassword',
      };
      const sendOtpError = new Error('Failed to send OTP');

      // Mock findUserByEmail to return an existing user
      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(existingUser);

      // Mock verifyUserExist to do nothing when user exists
      jest.spyOn(authService, 'verifyUserExist').mockImplementation((user, callback, message) => {
        if (!user) {
          callback();
        }
      });

      // Mock updateForgetPasswordField to return undefined (resolved)
      jest.spyOn(authService, 'updateForgotPasswordStatus').mockResolvedValue(undefined);

      // Mock sendOtp to throw an error
      jest.spyOn(authService, 'sendOtp').mockRejectedValue(sendOtpError);

      await expect(authService.forgetPassword(forgetData)).rejects.toThrow(sendOtpError);
      expect(authService.findUserByEmail).toHaveBeenCalledWith(forgetData.email);
      expect(authService.verifyUserExist).toHaveBeenCalledWith(existingUser, expect.any(Function), otpEmailSendFail);
      expect(authService.updateForgotPasswordStatus).toHaveBeenCalledWith(existingUser.email, true);
      expect(authService.sendOtp).toHaveBeenCalledWith(existingUser.email);
    });
  });

  describe('changePassword', () => {
    it('should throw an error if user does not exist', async () => {
      const changePasswordData: ChangePasswordDto = {
        oldPassword: 'oldPassword123',
        newPassword: 'newPassword123',
      };
      const req = { user: { email: 'nonexistent@example.com' } };

      // Mock findUserByEmail to return null, simulating that the user does not exist
      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(null);

      await expect(authService.changePassword(changePasswordData, req)).rejects.toThrow(BadRequestException);
      expect(authService.findUserByEmail).toHaveBeenCalledWith(req.user.email);
    });

    it('should successfully change password if user exists and passwords match', async () => {
      const changePasswordData: ChangePasswordDto = {
        oldPassword: 'oldPassword123',
        newPassword: 'newPassword123',
      };
      const req = { user: { email: 'test@example.com' } };

      const existingUser = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        verified: true,
        isForgetPassword: false,
        password: 'hashedOldPassword',
      };

      // Mock findUserByEmail to return the existing user
      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(existingUser);

      // Mock verifyUserAndChangePassword to resolve successfully
      jest.spyOn(authService, 'verifyUserAndChangePassword').mockResolvedValue(undefined);

      // Mock updatePassword to resolve successfully
      jest.spyOn(authService, 'updatePassword').mockResolvedValue(undefined);

      // Expected response
      const expectedResponse = {
        success: true,
        message: yourPasswordHasBeenUpdated,
      };

      // Act: Execute the method
      const result = await authService.changePassword(changePasswordData, req);

      expect(authService.findUserByEmail).toHaveBeenCalledWith(req.user.email);
      expect(authService.verifyUserAndChangePassword).toHaveBeenCalledWith(existingUser, changePasswordData, req);
      expect(authService.updatePassword).toHaveBeenCalledWith(existingUser, changePasswordData.newPassword);
      expect(result).toEqual(expectedResponse);
    });

    it('should handle errors from verifyUserAndChangePassword correctly', async () => {
      const changePasswordData: ChangePasswordDto = {
        oldPassword: 'oldPassword123',
        newPassword: 'newPassword123',
      };
      const req = { user: { email: 'test@example.com' } };

      const existingUser = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        verified: true,
        isForgetPassword: false,
        password: 'hashedOldPassword',
        createdAt: new Date(),
        updatedAt: new Date(),
      };

      const verifyUserAndChangePasswordError = new Error('Failed to verify user and change password');

      // Mock findUserByEmail to return the existing user
      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(existingUser);

      // Mock verifyUserAndChangePassword to throw an error
      jest.spyOn(authService, 'verifyUserAndChangePassword').mockRejectedValue(verifyUserAndChangePasswordError);

      await expect(authService.changePassword(changePasswordData, req)).rejects.toThrow(verifyUserAndChangePasswordError);
      expect(authService.findUserByEmail).toHaveBeenCalledWith(req.user.email);
      expect(authService.verifyUserAndChangePassword).toHaveBeenCalledWith(existingUser, changePasswordData, req);
    });

    it('should handle errors from updatePassword correctly', async () => {
      const changePasswordData: ChangePasswordDto = {
        oldPassword: 'oldPassword123',
        newPassword: 'newPassword123',
      };
      const req = { user: { email: 'test@example.com' } };

      const existingUser = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        verified: true,
        isForgetPassword: false,
        password: 'hashedOldPassword',
      };

      const updatePasswordError = new Error('Failed to update password');

      // Mock findUserByEmail to return the existing user
      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(existingUser);

      // Mock verifyUserAndChangePassword to resolve successfully
      jest.spyOn(authService, 'verifyUserAndChangePassword').mockResolvedValue(undefined);

      // Mock updatePassword to throw an error
      jest.spyOn(authService, 'updatePassword').mockRejectedValue(updatePasswordError);

      await expect(authService.changePassword(changePasswordData, req)).rejects.toThrow(updatePasswordError);
      expect(authService.findUserByEmail).toHaveBeenCalledWith(req.user.email);
      expect(authService.verifyUserAndChangePassword).toHaveBeenCalledWith(existingUser, changePasswordData, req);
      expect(authService.updatePassword).toHaveBeenCalledWith(existingUser, changePasswordData.newPassword);
    });
  });

  describe('refreshToken', () => {
    it('should throw HttpException if user does not exist', async () => {
      const req = { user: { email: 'nonexistent@example.com' } };

      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(null);
      jest.spyOn(authService, 'verifyUserExist').mockImplementation((user, callback, message) => {
        if (!user) {
          callback();
        }
      });

      await expect(authService.refreshToken(req)).rejects.toThrow(HttpException);
      expect(authService.findUserByEmail).toHaveBeenCalledWith(req.user.email);
      expect(authService.verifyUserExist).toHaveBeenCalledWith(null, expect.any(Function), userNotFound);
    });

    it('should generate a new token and return it if user exists', async () => {
      const req = { user: { email: 'test@example.com' } };

      const existingUser: ExistingUserDto = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        verified: true,
        isForgetPassword: false,
        password: 'hashedPassword',
      };

      const sanitizedUserDataForToken: TokenPayloadDto = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        verified: true,
        isForgetPassword: false,
      };

      const tokens = { accessToken: 'newAccessToken', refreshToken: 'newRefreshToken' };

      jest.spyOn(authService, 'findUserByEmail').mockResolvedValue(existingUser);
      jest.spyOn(authService, 'verifyUserExist').mockImplementation((user, callback, message) => {
        if (!user) {
          callback();
        }
      });
      jest.spyOn(authService, 'removeSensitiveData').mockReturnValue(sanitizedUserDataForToken);
      jest.spyOn(authService, 'generateTokens').mockResolvedValue(tokens);

      const result = await authService.refreshToken(req);

      expect(authService.findUserByEmail).toHaveBeenCalledWith(req.user.email);
      expect(authService.verifyUserExist).toHaveBeenCalledWith(existingUser, expect.any(Function), userNotFound);
      expect(authService.removeSensitiveData).toHaveBeenCalledWith(existingUser, ['password']);
      expect(authService.generateTokens).toHaveBeenCalledWith(sanitizedUserDataForToken);
      expect(result).toEqual({ success: true, message: sucessfullyGenerateNewTokens, tokens: tokens });
    });
  });


  //-----------------------------------------------------------------------------
  //--------------------------reuse method test----------------------------------
  //-----------------------------------------------------------------------------

  describe('randomPasswordGenerator', () => {
    it('should generate a random password of the given length', () => {
      const length = 10; // Define the desired length of the password
      const password = authService.randomPasswordGenerator(length); // Generate the password

      expect(password).toHaveLength(length);
    });

    it('should include at least one digit as the first character', () => {
      const length = 10; // Define the desired length of the password
      const password = authService.randomPasswordGenerator(length); // Generate the password

      // Assert that the first character of the generated password is a digit
      expect(password[0]).toMatch(/\d/);
    });

    it('should only contain characters from the specified charset', () => {
      const length = 10; // Define the desired length of the password
      const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?'; // Define the allowed charset
      const password = authService.randomPasswordGenerator(length); // Generate the password

      // Loop through each character in the generated password and assert that it is within the allowed charset
      for (const char of password) {
        expect(charset).toContain(char);
      }
    });

    it('should generate different passwords on successive calls', () => {
      const length = 10; // Define the desired length of the password
      const password1 = authService.randomPasswordGenerator(length); // Generate the first password
      const password2 = authService.randomPasswordGenerator(length); // Generate the second password

      // Assert that the two generated passwords are not the same
      expect(password1).not.toEqual(password2);
    });
  });

  describe('verifyOtp', () => {
    const email = 'test@example.com';
    const dbOTP = '123456';

    it('should throw UnauthorizedException if OTP is invalid or expired', async () => {
      prismaService.OTP.findUnique.mockResolvedValue({
        otp: dbOTP,
        expiresAt: new Date(Date.now() - 10000), // expired
      });

      await expect(authService.verifyOtp(email, dbOTP)).rejects.toThrow(UnauthorizedException);
    });

    it('should not throw if OTP is valid', async () => {
      prismaService.OTP.findUnique.mockResolvedValue({
        otp: dbOTP,
        expiresAt: new Date(Date.now() + 10000), // valid
      });

      await expect(authService.verifyOtp(email, dbOTP)).resolves.not.toThrow();
    });

    it('should throw UnauthorizedException if OTP does not match', async () => {
      prismaService.OTP.findUnique.mockResolvedValue({
        otp: '654321',
        expiresAt: new Date(Date.now() + 10000), // valid
      });

      await expect(authService.verifyOtp(email, dbOTP)).rejects.toThrow(UnauthorizedException);
    });

    it('should throw UnauthorizedException if OTP record is not found', async () => {
      prismaService.OTP.findUnique.mockResolvedValue(null);

      await expect(authService.verifyOtp(email, dbOTP)).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('generateJwtAccessToken', () => {
    it('should generate and encrypt a JWT access token', async () => {
      const existingUser: ExistingUserDto = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        password: 'hashedpassword',
        verified: true,
        isForgetPassword: false,
      };

      const expectedPayload = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
      };

      const jwtToken = 'mockedJwtToken';
      const encryptedToken = 'mockedEncryptedToken';

      // Mocking the removeSensitiveData method to return the expected payload
      jest.spyOn(authService, 'removeSensitiveData').mockReturnValue(expectedPayload);

      // Mocking the sign method of jwtService to return the JWT token
      (jwtService.sign as jest.Mock).mockReturnValue(jwtToken);

      // Mocking the CompactEncrypt to return the encrypted token
      jest.spyOn(CompactEncrypt.prototype, 'encrypt').mockResolvedValue(encryptedToken);

      // Mocking TextEncoder to return the expected encoded values
      const mockTextEncoderInstance = {
        encode: jest.fn().mockReturnValue(new Uint8Array(jwtToken.split('').map(char => char.charCodeAt(0)))),
        encodeInto: jest.fn(),
      };

      jest.spyOn(global as any, 'TextEncoder').mockImplementation(() => mockTextEncoderInstance);

      const result = await authService.generateJwtAccessToken(jwtService, existingUser);


      expect(result).toBe(encryptedToken);
      expect(authService.removeSensitiveData).toHaveBeenCalledWith(existingUser, ['password', 'updatedAt', 'createdAt']);
      expect(jwtService.sign).toHaveBeenCalledWith(expectedPayload, {
        expiresIn: authService['jwejwtAccessTokenExpireTime'],
        secret: authService['jwtAccessTokenSecrectKey'],
      });
      expect(CompactEncrypt.prototype.encrypt).toHaveBeenCalledWith(expect.any(Uint8Array));
      expect(mockTextEncoderInstance.encode).toHaveBeenCalledWith(jwtToken);
    });
  });

  describe('generateJwtRefreshToken', () => {
    it('should generate and encrypt a JWT refresh token', async () => {
      const existingUser = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        password: 'hashedpassword',
        verified: true,
        isForgetPassword: false,
      };

      const expectedPayload = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
      };

      const jwtToken = 'mockedJwtToken';
      const encryptedToken = 'mockedEncryptedToken';

      // Mocking the removeSensitiveData method to return the expected payload
      jest.spyOn(authService, 'removeSensitiveData').mockReturnValue(expectedPayload);

      // Mocking the sign method of jwtService to return the JWT token
      (jwtService.sign as jest.Mock).mockReturnValue(jwtToken);

      // Mocking the CompactEncrypt to return the encrypted token
      jest.spyOn(CompactEncrypt.prototype, 'encrypt').mockResolvedValue(encryptedToken);

      // Mocking TextEncoder to return the expected encoded values
      const mockTextEncoderInstance = {
        encode: jest.fn().mockReturnValue(new Uint8Array(jwtToken.split('').map(char => char.charCodeAt(0)))),
        encodeInto: jest.fn(),
      };

      jest.spyOn(global as any, 'TextEncoder').mockImplementation(() => mockTextEncoderInstance);

      const result = await authService.generateJwtRefreshToken(jwtService, existingUser);

      expect(result).toBe(encryptedToken);
      expect(authService.removeSensitiveData).toHaveBeenCalledWith(existingUser, ['password', 'updatedAt', 'createdAt']);
      expect(jwtService.sign).toHaveBeenCalledWith(expectedPayload, {
        expiresIn: authService['jwejwtRefreshTokenExpireTime'],
        secret: authService['jwtRefreshTokenSecrectKey'],
      });
      expect(CompactEncrypt.prototype.encrypt).toHaveBeenCalledWith(expect.any(Uint8Array));
      expect(mockTextEncoderInstance.encode).toHaveBeenCalledWith(jwtToken);
    });
  });

  describe('generateToken', () => {
    it('should generate both accessToken and refreshToken', async () => {
      // Create a mock user object
      const user: ExistingUserDto = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        password: 'hashedpassword',
        verified: true,
        isForgetPassword: false,
      };


      // Define the expected user object without sensitive data
      const userWithoutSensitiveData = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
      };

      // Define the mock access token and refresh token
      const accessToken = 'mockedAccessToken';
      const refreshToken = 'mockedRefreshToken';

      // Mock the removeSensitiveData method to return the user without sensitive data
      jest.spyOn(authService, 'removeSensitiveData').mockReturnValue(userWithoutSensitiveData);

      // Mock the generateJwtAccessToken method to return the mock access token
      jest.spyOn(authService, 'generateJwtAccessToken').mockResolvedValue(accessToken);

      // Mock the generateJwtRefreshToken method to return the mock refresh token
      jest.spyOn(authService, 'generateJwtRefreshToken').mockResolvedValue(refreshToken);

      // Call the generateToken method
      const result = await authService.generateTokens(user);

      // Verify that removeSensitiveData was called with the correct arguments
      expect(authService.removeSensitiveData).toHaveBeenCalledWith(user, ['password']);

      // Verify that generateJwtAccessToken was called with the correct arguments
      expect(authService.generateJwtAccessToken).toHaveBeenCalledWith(jwtService, userWithoutSensitiveData);

      // Verify that generateJwtRefreshToken was called with the correct arguments
      expect(authService.generateJwtRefreshToken).toHaveBeenCalledWith(jwtService, userWithoutSensitiveData);

      // Verify that the result matches the expected access token and refresh token
      expect(result).toEqual({ accessToken, refreshToken });
    });
  });

  describe('sendOtpEmail', () => {
    beforeEach(() => {
      jest.clearAllMocks(); // Clear all mocks before each test
    });

    it('should send OTP email successfully', async () => {
      const email = 'test@example.com';
      const otp = '123456';
      const expireTime = 10;

      // Call the sendOtpEmail method
      await authService.sendOtpEmail(email, otp, expireTime);

      // Assert that the sendMail method of mailerService is called with the correct parameters
      expect(mailerService.sendMail).toHaveBeenCalledWith({
        to: email,
        from: 'noreply@example.com',
        subject: emailSubject,
        text: `Your OTP code is: ${otp}. It is valid for ${expireTime} minutes.`,
      });
    });

    it('should throw InternalServerErrorException if email sending fails', async () => {
      const email = 'test@example.com';
      const otp = '123456';
      const expireTime = 10;
      const error = new Error('SMTP server error');

      // Mock the sendMail method to simulate a failure
      (mailerService.sendMail as jest.Mock).mockRejectedValueOnce(error);

      // Assert that the sendOtpEmail method throws an InternalServerErrorException
      await expect(authService.sendOtpEmail(email, otp, expireTime)).rejects.toThrow(InternalServerErrorException);

      // Assert that console.error is called with the correct message and error
      expect(console.error).toHaveBeenCalledWith(failedToSendOTPEmail, error);
    });
  });

  describe('storeOtp', () => {
    it('should store OTP with the correct expiry time', async () => {
      const email = 'test@example.com';
      const otp = '123456';

      // Mock the upsert method of prismaService to simulate successful storage
      prismaService.OTP.upsert = jest.fn().mockResolvedValue(undefined);

      // Call the storeOtp method
      await authService.storeOtp(email, otp);

      expect(prismaService.OTP.upsert).toHaveBeenCalledWith({
        where: { email },
        update: { otp, expiresAt: expect.any(Date) },
        create: { email, otp, expiresAt: expect.any(Date) },
      });

      const calledArgs = prismaService.OTP.upsert.mock.calls[0][0];

      expect(calledArgs.update.expiresAt).toBeInstanceOf(Date);
      expect(calledArgs.create.expiresAt).toBeInstanceOf(Date);
    });
  });

  describe('generateOtp', () => {
    it('should generate an OTP of the specified length', () => {
      const length = 6;
      const otp = authService['generateOtp'](length);

      expect(otp).toHaveLength(length);
    });

    it('should generate an OTP containing only digits', () => {
      const length = 6;
      const otp = authService['generateOtp'](length);

      // Assert that the OTP contains only digits
      expect(otp).toMatch(/^\d+$/);
    });

    it('should generate different OTPs on successive calls', () => {
      const length = 6;
      const otp1 = authService['generateOtp'](length); // Generate first OTP
      const otp2 = authService['generateOtp'](length); // Generate second OTP

      // Assert that the two generated OTPs are not the same
      expect(otp1).not.toEqual(otp2);
    });
  });

  describe('updatePassword', () => {
    beforeEach(() => {
      jest.clearAllMocks(); // Clear all mocks before each test
      // Mock bcrypt.hash function inside beforeEach
      jest.spyOn(bcrypt, 'hash').mockImplementation((password, salt) => Promise.resolve(`hashed_${password}`));
    });

    it('should hash the new password and update the user record', async () => {
      const user = { id: 1 } as ExistingUserDto;
      const newPassword = 'newPassword123';

      // Mock the resolved value of the update function
      jest.spyOn(prismaService.user, 'update').mockResolvedValue({
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        password: `hashed_${newPassword}`,
        loginSource: 'local',
        authorizerId: 'auth123',
        verified: true,
        isForgetPassword: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      });

      await authService.updatePassword(user, newPassword);

      expect(bcrypt.hash).toHaveBeenCalledWith(newPassword, authService['saltRounds']);
      expect(prismaService.user.update).toHaveBeenCalledWith({
        where: { id: user.id },
        data: { password: `hashed_${newPassword}`, isForgetPassword: false },
      });
    });

    // Clean up mocks after tests
    afterEach(() => {
      jest.clearAllMocks();
    });
  });

  describe('verifyUserAndChangePassword', () => {
    it('should throw BadRequestException if user does not exist', async () => {
      const existingUser: ExistingUserDto = null;
      const changePasswordData: ChangePasswordDto = { oldPassword: 'oldPass', newPassword: 'newPass' };
      const req = { user: { isForgetPassword: false } };

      // Mock the removeSensitiveData method to return an empty object
      jest.spyOn(authService, 'removeSensitiveData').mockReturnValue({});

      // Expect the function to throw a BadRequestException when user does not exist
      await expect(authService.verifyUserAndChangePassword(existingUser, changePasswordData, req)).rejects.toThrow(BadRequestException);
    });

    it('should return if it is a forget password case', async () => {
      const existingUser = { isForgetPassword: true, verified: true } as ExistingUserDto;
      const changePasswordData: ChangePasswordDto = { oldPassword: 'oldPass', newPassword: 'newPass' };
      const req = { user: { isForgetPassword: true } };

      // Expect the function to resolve without throwing an error in a forget password case
      await expect(authService.verifyUserAndChangePassword(existingUser, changePasswordData, req)).resolves.toBeUndefined();
    });

    it('should throw BadRequestException if old password is not provided', async () => {
      const existingUser = { isForgetPassword: false, verified: true } as ExistingUserDto;
      const changePasswordData: ChangePasswordDto = { oldPassword: '', newPassword: 'newPass' };
      const req = { user: { isForgetPassword: false } };

      // Mock the removeSensitiveData method to return an object without the password
      jest.spyOn(authService, 'removeSensitiveData').mockReturnValue({ id: 1, email: 'test@example.com' });

      // Expect the function to throw a BadRequestException when the old password is not provided
      await expect(authService.verifyUserAndChangePassword(existingUser, changePasswordData, req)).rejects.toThrow(BadRequestException);
    });

    it('should throw BadRequestException if old password does not match', async () => {
      const existingUser = {
        isForgetPassword: false,
        verified: true,
        password: 'hashedPassword',
      } as ExistingUserDto;
      const changePasswordData: ChangePasswordDto = { oldPassword: 'oldPass', newPassword: 'newPass' };
      const req = { user: { isForgetPassword: false } };

      // Mock bcrypt.compare to return false, indicating the passwords do not match
      (bcrypt.compare as jest.Mock).mockResolvedValueOnce(Promise.resolve(false));

      // Mock the removeSensitiveData method to return an object without the password
      jest.spyOn(authService, 'removeSensitiveData').mockReturnValue({ id: 1, email: 'test@example.com' });

      // Expect the function to throw a BadRequestException when the passwords do not match
      await expect(authService.verifyUserAndChangePassword(existingUser, changePasswordData, req)).rejects.toThrow(BadRequestException);
    });

    it('should return if old password matches', async () => {
      const existingUser = {
        isForgetPassword: false,
        verified: true,
        password: 'hashedPassword',
      } as ExistingUserDto;
      const changePasswordData: ChangePasswordDto = { oldPassword: 'oldPass', newPassword: 'newPass' };
      const req = { user: { isForgetPassword: false } };

      // Mock bcrypt.compare to return true, indicating the passwords match
      (bcrypt.compare as jest.Mock).mockResolvedValueOnce(Promise.resolve(true));

      // Expect the function to resolve without throwing an error when the passwords match
      await expect(authService.verifyUserAndChangePassword(existingUser, changePasswordData, req)).resolves.toBeUndefined();
    });
  });

  describe('updateUserVerificationStatus', () => {
    it('should update user verification status', async () => {
      const email = 'test@example.com';
      const verified = true;

      await authService.updateUserVerificationStatus(email, verified);

      // Expect the PrismaService update method to be called with the correct parameters
      expect(prismaService.user.update).toHaveBeenCalledWith({
        where: { email },
        data: { verified },
      });
    });
  });

  describe('updateForgetPasswordField', () => {
    it('should update the isForgetPassword field correctly', async () => {
      const email = 'test@example.com';
      const boolValue = true;

      // Mock the resolved value of the update function
      jest.spyOn(prismaService.user, 'update').mockResolvedValue({
        email,
        isForgetPassword: boolValue,
      } as any);

      // Call the updateForgetPasswordField method
      await authService.updateForgotPasswordStatus(email, boolValue);

      // Expect the PrismaService update method to be called with the correct parameters
      expect(prismaService.user.update).toHaveBeenCalledWith({
        where: { email },
        data: { isForgetPassword: boolValue },
      });
    });
  });

  describe('deleteOtp', () => {
    it('should delete OTP for the given email', async () => {
      const email = 'test@example.com';

      // Mock the resolved value of the delete function
      prismaService.OTP.delete = jest.fn().mockResolvedValue({});

      // Call the deleteOtp method
      await authService.deleteOtp(email);

      // Verify that the delete function was called with the correct parameters
      expect(prismaService.OTP.delete).toHaveBeenCalledWith({
        where: { email },
      });
    });
  });

  describe('verifyUserExist', () => {
    it('should call the callback if user does not exist', () => {
      const user: ExistingUserDto = null;
      const callback = jest.fn();
      const message = 'User not found';

      // Mock the removeSensitiveData method to return an empty object
      jest.spyOn(authService, 'removeSensitiveData').mockReturnValue({});

      // Call the verifyUserExist method
      authService.verifyUserExist(user, callback, message);

      // Verify that the callback was called
      expect(callback).toHaveBeenCalled();
    });

    it('should not call the callback if user exists', () => {
      const user = { id: 1, email: 'test@example.com', password: 'hashedpassword' } as ExistingUserDto;
      const callback = jest.fn();
      const message = 'User not found';

      // Mock the removeSensitiveData method to return an object without the password
      jest.spyOn(authService, 'removeSensitiveData').mockReturnValue({ id: 1, email: 'test@example.com' });

      // Call the verifyUserExist method
      authService.verifyUserExist(user, callback, message);

      // Verify that the callback was not called
      expect(callback).not.toHaveBeenCalled();
    });
  });

  describe('verifyUserAndOtp', () => {
    it('should call verifyUserExist and throw NotFoundException if user does not exist', async () => {
      const user: ExistingUserDto = null; // Simulating that user does not exist
      const otp = '123456';

      // Mock verifyUserExist to simulate user does not exist
      jest.spyOn(authService, 'verifyUserExist').mockImplementationOnce((user, callback, message) => {
        if (!user) {
          callback();
        }
      });

      // Assert that verifyUserAndOtp throws NotFoundException
      await expect(authService.verifyUserAndOtp(user, otp)).rejects.toThrow(NotFoundException);
      expect(authService.verifyUserExist).toHaveBeenCalledWith(user, expect.any(Function), otpVerificationFailed);
    });

    it('should call verifyOtp if user exists', async () => {
      const user = { email: 'test@example.com' } as ExistingUserDto;
      const otp = '123456';

      // Mock verifyUserExist to simulate user exists
      jest.spyOn(authService, 'verifyUserExist').mockImplementationOnce((user, callback, message) => {
        if (!user) {
          callback();
        }
      });

      // Mock verifyOtp to resolve successfully
      jest.spyOn(authService, 'verifyOtp').mockResolvedValueOnce(undefined);

      // Assert that verifyUserAndOtp does not throw an error
      await expect(authService.verifyUserAndOtp(user, otp)).resolves.toBeUndefined();
      expect(authService.verifyUserExist).toHaveBeenCalledWith(user, expect.any(Function), otpVerificationFailed);
      expect(authService.verifyOtp).toHaveBeenCalledWith(user.email, otp);
    });
  });

  describe('buildSigninResponse', () => {
    it('should build and return a signin response object', () => {
      const user = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
      };

      // Mock token object
      const token = {
        accessToken: 'mockedAccessToken',
        refreshToken: 'mockedRefreshToken',
      };

      // Mock message
      const message = 'signinSuccessful';

      // Expected response object
      const expectedResponse = {
        success: true,
        message: message,
        tokens: {
          accessToken: token.accessToken,
          refreshToken: token.refreshToken,
        },
        data: {
          user: user,
        },
      };

      // Call the buildSigninResponse method
      const response = authService.buildSigninResponse(user, token, message);

      // Assert that the response matches the expected response
      expect(response).toEqual(expectedResponse);
    });
  });

  describe('authenticateUser', () => {
    it('should throw UnauthorizedException if user does not exist', () => {
      const user = null; // Simulating that user does not exist
      const password = 'testPassword';

      // Mock the removeSensitiveData method to return an empty object
      jest.spyOn(authService, 'removeSensitiveData').mockReturnValue({});

      // Expect the authenticateUser function to throw an UnauthorizedException
      expect(() => authService.authenticateUser(user, password)).toThrow(UnauthorizedException);
    });

    // Test case to check if UnauthorizedException is thrown when the password does not match
    it('should throw UnauthorizedException if password does not match', () => {
      const user = { password: 'hashedPassword' } as ExistingUserDto; // Mock user object with a hashed password
      const password = 'testPassword';

      // Mock bcrypt.compareSync to return false, indicating the passwords do not match
      jest.spyOn(bcrypt, 'compareSync').mockReturnValueOnce(false);

      // Mock the removeSensitiveData method to return an object without the password
      jest.spyOn(authService, 'removeSensitiveData').mockReturnValue({ id: 1, email: 'test@example.com' });

      // Expect the authenticateUser function to throw an UnauthorizedException
      expect(() => authService.authenticateUser(user, password)).toThrow(UnauthorizedException);

      // Verify that the logger.error method was called with the correct parameters
      expect(logger.error).toHaveBeenCalledWith({
        message: `${unauthorized} because user password not matched`,
        details: { id: 1, email: 'test@example.com' },
      });
    });

    // Test case to check if ForbiddenException is thrown when the user is not verified
    it('should throw ForbiddenException if user is not verified', () => {
      const user = { password: 'hashedPassword', verified: false } as ExistingUserDto; // Mock user object with a non-verified status
      const password = 'testPassword';

      // Mock bcrypt.compareSync to return true, indicating the passwords match
      jest.spyOn(bcrypt, 'compareSync').mockReturnValueOnce(true);

      // Mock the removeSensitiveData method to return an object without the password
      jest.spyOn(authService, 'removeSensitiveData').mockReturnValue({ id: 1, email: 'test@example.com' });

      // Expect the authenticateUser function to throw a ForbiddenException
      expect(() => authService.authenticateUser(user, password)).toThrow(ForbiddenException);

      // Verify that the logger.error method was called with the correct parameters
      expect(logger.error).toHaveBeenCalledWith({
        message: `${verifyYourUser}`,
        details: { id: 1, email: 'test@example.com' },
      });
    });

    // Test case to check if no exception is thrown when the user is authenticated successfully
    it('should not throw if user is authenticated successfully', () => {
      const user = { password: 'hashedPassword', verified: true } as ExistingUserDto; // Mock user object with a verified status
      const password = 'testPassword';

      // Mock bcrypt.compareSync to return true, indicating the passwords match
      jest.spyOn(bcrypt, 'compareSync').mockReturnValueOnce(true);

      // Expect the authenticateUser function not to throw any exception
      expect(() => authService.authenticateUser(user, password)).not.toThrow();
    });
  });

  describe('createUser', () => {
    it('should create a user with the given data', async () => {
      // Mock user data to be provided as input
      const userData = {
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
      };

      // Mock password and other details
      const password = 'hashedPassword';
      const loginSource = 'local';
      const verified = true;

      // Mock the PrismaService create method to return the expected user data
      const expectedUser = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        verified: true,
        password: 'hashedPassword',
        isForgetPassword: false,
      };

      prismaService.user.create = jest.fn().mockResolvedValue(expectedUser);

      // Call the createUser method with the mock data
      const result = await authService.createUser(userData as SignupDto, password, loginSource, verified);

      // Expect the PrismaService create method to be called with the correct parameters
      expect(prismaService.user.create).toHaveBeenCalledWith({
        data: {
          ...userData,
          loginSource: loginSource,
          verified: verified,
          isForgetPassword: false,
          password: password,
        },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          verified: true,
          password: true,
          isForgetPassword: true,
        },
      });

      // Expect the result to match the expected user data
      expect(result).toEqual(expectedUser);
    });
  });

  describe('findUserByEmail', () => {
    it('should find a user by email', async () => {
      // Mock email for searching the user
      const email = 'test@example.com';

      // Mock the expected user data to be returned by Prisma
      const expectedUser: ExistingUserDto = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        password: 'hashedPassword',
        verified: true,
        isForgetPassword: false,
      };

      // Mock the PrismaService findUnique method to return the expected user data
      prismaService.user.findUnique = jest.fn().mockResolvedValue(expectedUser);

      // Call the findUserByEmail method with the mock email
      const result = await authService.findUserByEmail(email);

      // Expect the PrismaService findUnique method to be called with the correct parameters
      expect(prismaService.user.findUnique).toHaveBeenCalledWith({
        where: { email },
        select: {
          id: true,
          email: true,
          firstName: true,
          lastName: true,
          password: true,
          verified: true,
          isForgetPassword: true,
        },
      });

      // Expect the result to match the expected user data
      expect(result).toEqual(expectedUser);
    });
  });

  describe('sendOtp', () => {
    it('should send OTP to existing user', async () => {
      // Mock email for sending OTP
      const email = 'test@example.com';

      // Mock existing user data
      const existingUser: ExistingUserDto = {
        id: 1,
        email: 'test@example.com',
        firstName: 'John',
        lastName: 'Doe',
        password: 'hashedPassword',
        verified: true,
        isForgetPassword: false,
      };

      // Mock the findUserByEmail method to return the existing user
      authService.findUserByEmail = jest.fn().mockResolvedValue(existingUser);

      // Mock the generateOtp method to return a fixed OTP
      authService.generateOtp = jest.fn().mockReturnValue('123456');

      // Mock the storeOtp method
      authService.storeOtp = jest.fn();

      // Mock the sendOtpEmail method
      authService.sendOtpEmail = jest.fn();

      // Call the sendOtp method with the mock email
      const result = await authService.sendOtp(email);

      // Expectations

      // Verify that findUserByEmail method is called with the correct email
      expect(authService.findUserByEmail).toHaveBeenCalledWith(email);

      // Verify that generateOtp method is called
      expect(authService.generateOtp).toHaveBeenCalled();

      // Verify that storeOtp method is called with the correct parameters
      expect(authService.storeOtp).toHaveBeenCalledWith(email, '123456');

      // Verify that sendOtpEmail method is called with the correct parameters
      expect(authService.sendOtpEmail).toHaveBeenCalledWith(email, '123456', authService.otpExpireTime);

      // Verify the result
      expect(result).toEqual({
        success: true,
        message: otpEmailSend,
      });
    });
  });
});

