import {Inject, Injectable} from '@nestjs/common';
import type {PasswordHasherPort} from '../../domain/repositories/password-hasher.port';
import {PASSWORD_HASHER_PORT} from '../di-tokens';

/**
 * Password Policy Service
 * Application layer service for password hashing and generation
 * Following Clean Architecture: uses domain port, not infrastructure directly
 */
@Injectable()
export class PasswordPolicyService {
  constructor(
    @Inject(PASSWORD_HASHER_PORT)
    private readonly passwordHasher: PasswordHasherPort
  ) {}

  async hashPassword(password: string, saltRounds: number): Promise<string> {
    return this.passwordHasher.hash(password, saltRounds);
  }

  async comparePassword(plainPassword: string, hashedPassword: string): Promise<boolean> {
    return this.passwordHasher.compare(plainPassword, hashedPassword);
  }

  randomPasswordGenerator(length: number): string {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let code = '';

    const randomNumber = Math.floor(Math.random() * 10);
    code += randomNumber.toString();

    for (let i = 1; i < length; i++) {
      const randomIndex = Math.floor(Math.random() * charset.length);
      code += charset[randomIndex];
    }

    return code;
  }
}
