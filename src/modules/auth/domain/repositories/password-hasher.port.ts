/**
 * Password Hasher Port
 * Domain layer abstraction for password hashing operations
 * Following Clean Architecture: application depends on this abstraction, not concrete implementation
 */
export interface PasswordHasherPort {
  /**
   * Hash a plain text password
   * @param password - Plain text password to hash
   * @param saltRounds - Number of salt rounds for hashing (typically 10-12)
   * @returns Hashed password string
   */
  hash(password: string, saltRounds: number): Promise<string>;

  /**
   * Compare a plain text password with a hashed password
   * @param plainPassword - Plain text password to verify
   * @param hashedPassword - Hashed password to compare against
   * @returns True if passwords match, false otherwise
   */
  compare(plainPassword: string, hashedPassword: string): Promise<boolean>;

  /**
   * Synchronously compare a plain text password with a hashed password
   * Use sparingly - prefer async compare() method
   * @param plainPassword - Plain text password to verify
   * @param hashedPassword - Hashed password to compare against
   * @returns True if passwords match, false otherwise
   */
  compareSync(plainPassword: string, hashedPassword: string): boolean;
}
