import {Email} from '../value-objects/email.vo';
import {Password} from '../value-objects/password.vo';

export class User {
  constructor(
    public readonly id: number,
    public readonly email: Email,
    private password: Password,
    public readonly firstName: string | null,
    public readonly lastName: string | null,
    public readonly verified: boolean,
    public readonly loginSource: string,
    public readonly authorizerId: string | null,
    public readonly mfaEnabled: boolean,
    public readonly failedOtpAttempts: number,
    public readonly accountLockedUntil: Date | null,
    public readonly lastActivityAt: Date | null,
    public readonly logoutPin: string,
    public readonly createdAt: Date,
    public readonly updatedAt: Date
  ) {}

  updatePassword(newPassword: Password): void {
    this.password = newPassword;
  }

  getPassword(): Password {
    return this.password;
  }

  isVerified(): boolean {
    return this.verified;
  }

  isLocked(): boolean {
    if (!this.accountLockedUntil) {
      return false;
    }
    return new Date() < this.accountLockedUntil;
  }

  markAsVerified(): User {
    return new User(
      this.id,
      this.email,
      this.password,
      this.firstName,
      this.lastName,
      true,
      this.loginSource,
      this.authorizerId,
      this.mfaEnabled,
      this.failedOtpAttempts,
      this.accountLockedUntil,
      this.lastActivityAt,
      this.logoutPin,
      this.createdAt,
      this.updatedAt
    );
  }
}
