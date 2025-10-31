export class Password {
  private constructor(private readonly hashedValue: string) {}

  static create(hashedPassword: string): Password {
    return new Password(hashedPassword);
  }

  getHashedValue(): string {
    return this.hashedValue;
  }

  equals(other: Password): boolean {
    return this.hashedValue === other.hashedValue;
  }
}
