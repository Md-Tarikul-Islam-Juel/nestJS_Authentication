import {Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';

/**
 * Password Validation Service
 * Application layer service containing business validation logic
 * Following Clean Architecture: business logic separated from framework concerns
 */
@Injectable()
export class PasswordValidationService {
  constructor(private readonly configService: ConfigService) {}

  /**
   * Validate password against all configured policy rules
   * @param password - The password to validate
   * @returns Object with isValid flag and error message if invalid
   */
  validatePassword(password: string): {isValid: boolean; error?: string} {
    if (!password || typeof password !== 'string') {
      return {isValid: false, error: 'Password is required'};
    }

    const minLength = this.configService.get<number>('authConfig.password.minLength', 8);
    const maxLength = this.configService.get<number>('authConfig.password.maxLength', 32);

    // Length validation
    if (password.length < minLength) {
      return {
        isValid: false,
        error: `Password must be at least ${minLength} characters long`
      };
    }

    if (password.length > maxLength) {
      return {
        isValid: false,
        error: `Password must be at most ${maxLength} characters long`
      };
    }

    // Character requirements
    const requireLowercase = this.configService.get<boolean>('authConfig.password.requireLowercase', true);
    if (requireLowercase && !/[a-z]/.test(password)) {
      return {
        isValid: false,
        error: 'Password must contain at least one lowercase letter'
      };
    }

    const requireUppercase = this.configService.get<boolean>('authConfig.password.requireUppercase', true);
    if (requireUppercase && !/[A-Z]/.test(password)) {
      return {
        isValid: false,
        error: 'Password must contain at least one uppercase letter'
      };
    }

    const requireNumbers = this.configService.get<boolean>('authConfig.password.requireNumbers', true);
    if (requireNumbers && !/\d/.test(password)) {
      return {
        isValid: false,
        error: 'Password must contain at least one number'
      };
    }

    const requireSpecialChars = this.configService.get<boolean>('authConfig.password.requireSpecialCharacters', true);
    if (requireSpecialChars) {
      const specialChars = this.configService.get<string>('authConfig.password.specialCharacters', '!@#$%^&*()_+[]{}|;:,.<>?');
      const escaped = specialChars.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&');
      const regex = new RegExp(`[${escaped}]`);
      if (!regex.test(password)) {
        return {
          isValid: false,
          error: `Password must contain at least one special character (${specialChars})`
        };
      }
    }

    // Pattern restrictions
    const disallowRepeating = this.configService.get<boolean>('authConfig.password.disallowRepeating', true);
    if (disallowRepeating && /(.)\1{1,}/.test(password)) {
      return {
        isValid: false,
        error: 'Password must not contain consecutive repeating characters'
      };
    }

    const disallowSequential = this.configService.get<boolean>('authConfig.password.disallowSequential', true);
    if (disallowSequential) {
      const sequentialPattern =
        /(?:012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)/i;
      if (sequentialPattern.test(password)) {
        return {
          isValid: false,
          error: 'Password must not contain sequential characters'
        };
      }
    }

    // Blacklist check
    const blacklistCommon = this.configService.get<boolean>('authConfig.password.blacklistCommon', true);
    if (blacklistCommon) {
      const blockedPasswords = this.configService.get<string[]>('authConfig.password.blockedPasswords', [
        '123456',
        'password',
        '123456789',
        'qwerty',
        '12345',
        '12345678',
        'abc123',
        'password1'
      ]);
      if (blockedPasswords.includes(password.toLowerCase())) {
        return {
          isValid: false,
          error: 'The password provided is too common and not allowed.'
        };
      }
    }

    return {isValid: true};
  }
}
