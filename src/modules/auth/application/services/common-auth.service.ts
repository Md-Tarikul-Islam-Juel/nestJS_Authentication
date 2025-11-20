import { Injectable } from '@nestjs/common';
import type { TokenPayload } from '../../domain/repositories/jwt-service.port';
import type { ExistingUserInterface } from '../types/auth.types';

/**
 * Common Auth Service
 * Application layer service for common auth-related operations
 * Used by application use-cases for data sanitization and common utilities
 */
@Injectable()
export class CommonAuthService {
  /**
   * Remove sensitive fields from an object
   * @param obj - Object to sanitize
   * @param sensitiveFields - Array of field names to remove
   * @returns New object with sensitive fields removed (shallow copy)
   *
   * @example
   * removeSensitiveData({ email: 'test@example.com', password: 'secret' }, ['password'])
   * // Returns: { email: 'test@example.com' }
   */
  removeSensitiveData<T extends Record<string, any>>(obj: T, sensitiveFields: string[]): Partial<T> {
    const filteredObj = {...obj};

    sensitiveFields.forEach(field => {
      delete filteredObj[field];
    });

    return filteredObj;
  }

  /**
   * Sanitize user data for token generation
   * Ensures required fields (id, email) are preserved while removing sensitive data
   * @param user - User object to sanitize (ExistingUserInterface or similar)
   * @param sensitiveFields - Array of field names to remove
   * @returns Sanitized TokenPayload with required fields preserved
   */
  sanitizeForToken(user: ExistingUserInterface | {id: number; email: string; [key: string]: unknown}, sensitiveFields: string[]): TokenPayload {
    const sanitized = {...user};

    sensitiveFields.forEach(field => {
      delete sanitized[field as keyof typeof sanitized];
    });

    // Ensure required fields are present
    if (!sanitized.id || !sanitized.email) {
      throw new Error('User object must contain id and email for token generation');
    }

    return sanitized as TokenPayload;
  }
}
