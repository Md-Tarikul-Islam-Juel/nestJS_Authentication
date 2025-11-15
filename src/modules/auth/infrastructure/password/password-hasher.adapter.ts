import {Injectable} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import type {PasswordHasherPort} from '../../domain/repositories/password-hasher.port';

/**
 * Password Hasher Adapter
 * Infrastructure layer implementation of PasswordHasherPort using bcrypt
 * Following Clean Architecture: implements domain port using infrastructure technology
 */
@Injectable()
export class PasswordHasherAdapter implements PasswordHasherPort {
  /**
   * Hash a plain text password using bcrypt
   * @param password - Plain text password to hash
   * @param saltRounds - Number of salt rounds for hashing (typically 10-12)
   * @returns Hashed password string
   */
  async hash(password: string, saltRounds: number): Promise<string> {
    return bcrypt.hash(password, saltRounds);
  }

  /**
   * Compare a plain text password with a hashed password using bcrypt
   * @param plainPassword - Plain text password to verify
   * @param hashedPassword - Hashed password to compare against
   * @returns True if passwords match, false otherwise
   */
  async compare(plainPassword: string, hashedPassword: string): Promise<boolean> {
    return bcrypt.compare(plainPassword, hashedPassword);
  }

  /**
   * Synchronously compare a plain text password with a hashed password using bcrypt
   * Use sparingly - prefer async compare() method
   * @param plainPassword - Plain text password to verify
   * @param hashedPassword - Hashed password to compare against
   * @returns True if passwords match, false otherwise
   */
  compareSync(plainPassword: string, hashedPassword: string): boolean {
    return bcrypt.compareSync(plainPassword, hashedPassword);
  }
}
