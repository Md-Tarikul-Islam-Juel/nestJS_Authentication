import {BadRequestException, ForbiddenException, Injectable, UnauthorizedException} from '@nestjs/common';
import {PrismaService} from '../../prisma/prisma.service';
import {SignupDto, OAuthDto, ChangePasswordDto} from '../dtos/authRequest.dto';
import {failedToChangePassword, oldPasswordIsRequired, unauthorized, verifyYourUser} from '../utils/string';
import * as bcrypt from 'bcrypt';
import {LoggerService} from '../../logger/logger.service';
import {CommonAuthService} from './commonAuth.service';
import {ExistingUserInterface} from '../interfaces/auth.interface';

@Injectable()
export class UserService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly commonAuthService: CommonAuthService,
    private logger: LoggerService
  ) {}

  async findUserByEmail(email: string): Promise<ExistingUserInterface> {
    return this.prisma.user.findUnique({
      where: {email}
    });
  }

  async createUser(userData: SignupDto | OAuthDto, password: string, loginSource: string, verified: boolean): Promise<ExistingUserInterface> {
    return this.prisma.user.upsert({
      where: {email: userData.email},
      update: {
        ...userData,
        loginSource: loginSource,
        verified: verified,
        isForgetPassword: false,
        password: password,
        mfaEnabled: userData.mfaEnabled || false,
        failedOtpAttempts: 0,
        logoutPin: this.commonAuthService.generateOtp(6)
      },
      create: {
        ...userData,
        loginSource: loginSource,
        verified: verified,
        isForgetPassword: false,
        password: password,
        mfaEnabled: userData.mfaEnabled || false,
        failedOtpAttempts: 0,
        logoutPin: this.commonAuthService.generateOtp(6)
      },
      select: {
        id: true,
        email: true,
        firstName: true,
        lastName: true,
        verified: true,
        password: true,
        isForgetPassword: true,
        mfaEnabled: true,
        failedOtpAttempts: true
      }
    });
  }

  async updateForgotPasswordStatus(email: string, boolValue: boolean): Promise<void> {
    this.prisma.user.update({
      where: {email},
      data: {isForgetPassword: boolValue}
    });
  }

  async updateUserVerificationStatus(email: string, verified: boolean): Promise<void> {
    await this.prisma.user.update({
      where: {email},
      data: {verified}
    });
  }

  // Authenticate user by email and password
  public authenticateUser(user: ExistingUserInterface, password: string): void {
    // Note: here bcrypt.compareSync(password.service.ts, user.password.service.ts) slow down the login process
    if (!user) {
      this.logger.error({
        message: `Authentication failed. User does not exist.${user.email}`,
        details: this.commonAuthService.removeSensitiveData(user, ['password'])
      });
      throw new UnauthorizedException({message: unauthorized});
    }
    if (!bcrypt.compareSync(password, user.password)) {
      this.logger.error({
        message: `Authentication failed. Incorrect password for user ${user.email}`,
        details: this.commonAuthService.removeSensitiveData(user, ['password'])
      });
      throw new UnauthorizedException({message: unauthorized});
    }
    if (!user.verified) {
      this.logger.error({
        message: `Authentication failed. User ${user.email} is not verified.`,
        details: this.commonAuthService.removeSensitiveData(user, ['password'])
      });
      throw new ForbiddenException({message: verifyYourUser});
    }
  }

  public verifyUserExist(user: ExistingUserInterface, callback: () => void, message: string): void {
    if (!user) {
      this.logger.error({
        message: `${message}`,
        details: this.commonAuthService.removeSensitiveData(user, ['password'])
      });
      callback();
    }
  }

  public async verifyUserAndChangePassword(existingUser: ExistingUserInterface, changePasswordData: ChangePasswordDto, req: any) {
    if (!existingUser) {
      this.logger.error({
        message: `${failedToChangePassword} because user not exist`,
        details: this.commonAuthService.removeSensitiveData(existingUser, ['password'])
      });
      throw new BadRequestException({message: failedToChangePassword});
    } else if (req.user.isForgetPassword === true && existingUser.isForgetPassword === true && existingUser.verified === true) {
      // ================================
      // this block for Forget password.service.ts
      // ================================
      return;
    } else if (req.user.isForgetPassword === false && existingUser.isForgetPassword === false && existingUser.verified === true) {
      // ================================
      // this block for change password.service.ts
      // ================================

      if (!changePasswordData.oldPassword) {
        this.logger.error({
          message: `${oldPasswordIsRequired}`,
          details: this.commonAuthService.removeSensitiveData(existingUser, ['password'])
        });
        throw new BadRequestException({message: oldPasswordIsRequired});
      }

      // Compare the provided password.service.ts with the hashed password.service.ts
      const passwordMatch: boolean = await bcrypt.compare(changePasswordData.oldPassword, existingUser.password);

      // If passwords don't match,
      if (!passwordMatch) {
        this.logger.error({
          message: `${failedToChangePassword} because password not matched`,
          details: this.commonAuthService.removeSensitiveData(existingUser, ['password'])
        });
        throw new BadRequestException({message: failedToChangePassword});
      } else if (passwordMatch) {
        return;
      }
    }

    this.logger.error({
      message: `${failedToChangePassword}`,
      details: this.commonAuthService.removeSensitiveData(existingUser, ['password'])
    });
    throw new BadRequestException({message: failedToChangePassword});
  }
}
