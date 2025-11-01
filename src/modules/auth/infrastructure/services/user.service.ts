import {Injectable} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import {LoggerService} from '../../../../common/observability/logger.service';
import {PrismaService} from '../../../../platform/prisma/prisma.service';
import {AUTH_MESSAGES} from '../../../_shared/constants';
import {ChangePasswordDto, OAuthDto, SignupDto} from '../../application/dto/auth-request.dto';
import {ExistingUserInterface} from '../../application/types/auth.types';
import {LoginSource} from '../../domain/enums/login-source.enum';
import {InvalidCredentialsError} from '../../domain/errors/invalid-credentials.error';
import {UserNotFoundError} from '../../domain/errors/user-not-found.error';
import {UserNotVerifiedError} from '../../domain/errors/user-not-verified.error';
import {CommonAuthService} from '../../domain/services/common-auth.service';

const failedToChangePassword = AUTH_MESSAGES.FAILED_TO_CHANGE_PASSWORD;
const oldPasswordIsRequired = AUTH_MESSAGES.OLD_PASSWORD_REQUIRED;
const unauthorized = AUTH_MESSAGES.UNAUTHORIZED;
const verifyYourUser = AUTH_MESSAGES.VERIFY_YOUR_USER;

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

  async createUser(userData: SignupDto | OAuthDto, password: string, loginSource: LoginSource, verified: boolean): Promise<ExistingUserInterface> {
    return this.prisma.user.upsert({
      where: {email: userData.email},
      update: {
        ...userData,
        loginSource: loginSource,
        verified: verified
      },
      create: {
        email: userData.email,
        password: password,
        firstName: userData.firstName,
        lastName: userData.lastName,
        loginSource: loginSource,
        verified: verified,
        mfaEnabled: userData.mfaEnabled || false,
        isForgetPassword: false,
        logoutPin: ''
      }
    });
  }

  async updateUserVerificationStatus(email: string, verified: boolean): Promise<void> {
    await this.prisma.user.update({
      where: {email},
      data: {verified}
    });
  }

  async updateForgotPasswordStatus(email: string, isForgetPassword: boolean): Promise<ExistingUserInterface> {
    return this.prisma.user.update({
      where: {email},
      data: {isForgetPassword}
    });
  }

  async updateLogoutPin(userId: number, logoutPin: string): Promise<void> {
    await this.prisma.user.update({
      where: {id: userId},
      data: {logoutPin}
    });
  }

  authenticateUser(user: ExistingUserInterface, password: string): void {
    if (!user) {
      this.logger.error(unauthorized, 'UserService.authenticateUser()', undefined, this.commonAuthService.removeSensitiveData(user, ['password']));
      throw new InvalidCredentialsError();
    }

    const isPasswordValid = bcrypt.compareSync(password, user.password);

    if (!isPasswordValid) {
      this.logger.error(
        `Authentication failed. Invalid password for user ${user.email}.`,
        'UserService.authenticateUser()',
        undefined,
        this.commonAuthService.removeSensitiveData(user, ['password'])
      );
      throw new InvalidCredentialsError();
    }

    if (!user.verified) {
      this.logger.error(
        `Authentication failed. User ${user.email} is not verified.`,
        'UserService.authenticateUser()',
        undefined,
        this.commonAuthService.removeSensitiveData(user, ['password'])
      );
      throw new UserNotVerifiedError(user.email);
    }
  }

  public verifyUserExist(user: ExistingUserInterface, callback: () => void, message: string): void {
    if (!user) {
      this.logger.error(message, 'UserService.verifyUserExist()', undefined, this.commonAuthService.removeSensitiveData(user, ['password']));
      callback();
    }
  }

  async verifyUserAndChangePassword(user: ExistingUserInterface, changePasswordData: ChangePasswordDto, req: any): Promise<void> {
    if (!user) {
      this.logger.error({
        message: `${failedToChangePassword} because user not exist`,
        details: this.commonAuthService.removeSensitiveData(user, ['password'])
      });
      throw new UserNotFoundError();
    }

    if (req.user.isForgetPassword === false) {
      if (!changePasswordData.oldPassword) {
        this.logger.error({
          message: `${oldPasswordIsRequired}`,
          details: this.commonAuthService.removeSensitiveData(user, ['password'])
        });
        throw new InvalidCredentialsError();
      }

      const isPasswordValid = bcrypt.compareSync(changePasswordData.oldPassword, user.password);
      if (!isPasswordValid) {
        this.logger.error({
          message: `${failedToChangePassword} because password not matched`,
          details: this.commonAuthService.removeSensitiveData(user, ['password'])
        });
        throw new InvalidCredentialsError();
      }
    }

    if (!user.verified) {
      this.logger.error({
        message: `${failedToChangePassword}`,
        details: this.commonAuthService.removeSensitiveData(user, ['password'])
      });
      throw new UserNotVerifiedError(user.email);
    }
  }
}
