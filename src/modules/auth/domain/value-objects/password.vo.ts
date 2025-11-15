const BCRYPT_HASH_REGEX = /^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$/;

export class Password {
  private constructor(private readonly hashedValue: string) {}

  static create(hashedPassword: string): Password {
    const sanitizedValue = hashedPassword.trim();

    if (!Password.isValidHash(sanitizedValue)) {
      throw new Error('Password must be a bcrypt hash');
    }

    return new Password(sanitizedValue);
  }

  getHashedValue(): string {
    return this.hashedValue;
  }

  equals(other: Password): boolean {
    return this.hashedValue === other.hashedValue;
  }

  private static isValidHash(value: string): boolean {
    return BCRYPT_HASH_REGEX.test(value);
  }
}
