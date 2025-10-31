import {Email} from '../../../auth/domain/value-objects/email.vo';

export class User {
  constructor(
    public readonly id: number,
    public readonly email: Email,
    public readonly firstName: string | null,
    public readonly lastName: string | null
  ) {}

  updateProfile(firstName?: string, lastName?: string): User {
    return new User(this.id, this.email, firstName ?? this.firstName, lastName ?? this.lastName);
  }

  getFullName(): string | null {
    if (this.firstName && this.lastName) {
      return `${this.firstName} ${this.lastName}`;
    }
    return this.firstName || this.lastName || null;
  }
}
