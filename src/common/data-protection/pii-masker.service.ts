import { Injectable } from '@nestjs/common';

/**
 * PII Masker Service
 * Automatically masks PII data in objects for safe logging
 * Following DATABASE_STANDARDS.md: "masking/redaction at ORM & log layers"
 */
@Injectable()
export class PiiMaskerService {
  /**
   * Mask PII fields in an object
   * @param obj - Object to mask
   * @returns Masked object (shallow copy)
   *
   * @example
   * piiMasker.maskObject({ email: 'john@example.com', password: 'secret123' })
   * // Returns: { email: 'jo***@example.com', password: '[REDACTED]' }
   */
  maskObject<T extends Record<string, any>>(obj: T | null | undefined): Partial<T> {
    if (!obj || typeof obj !== 'object') {
      return {} as Partial<T>;
    }

    const masked: Partial<T> = {};

    for (const [key, value] of Object.entries(obj)) {
      if (value === null || value === undefined) {
        masked[key as keyof T] = value;
        continue;
      }

      // Mask based on field name
      if (this.isSensitiveField(key)) {
        masked[key as keyof T] = this.maskSensitiveValue(key, value) as any;
      } else if (this.isPiiField(key)) {
        masked[key as keyof T] = this.maskPiiValue(value) as any;
      } else {
        masked[key as keyof T] = value;
      }
    }

    return masked;
  }

  /**
   * Mask PII in a string (useful for error messages)
   * @param message - String that may contain PII
   * @returns Masked string
   *
   * @example
   * piiMasker.maskString('Login failed for user john@example.com')
   * // Returns: 'Login failed for user jo***@example.com'
   */
  maskString(message: string): string {
    if (!message || typeof message !== 'string') {
      return message;
    }

    // Mask email addresses
    return message.replace(/\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g, match => {
      return this.maskEmail(match);
    });
  }

  /**
   * Deeply mask PII for any data structure (objects, arrays, primitives).
   * Useful for logging/interceptors where nested payloads may contain sensitive data.
   */
  maskDeep<T = unknown>(value: T): T {
    if (value === null || value === undefined) {
      return value;
    }

    if (Array.isArray(value)) {
      return value.map(item => this.maskDeep(item)) as unknown as T;
    }

    if (typeof value === 'object') {
      const maskedObject = this.maskObject(value as Record<string, any>);
      const result: Record<string, unknown> = {};
      for (const [key, nestedValue] of Object.entries(maskedObject)) {
        result[key] = this.maskDeep(nestedValue);
      }
      return result as T;
    }

    if (typeof value === 'string') {
      return this.maskString(value) as unknown as T;
    }

    return value;
  }

  /**
   * Check if a field is sensitive (should be completely redacted)
   */
  private isSensitiveField(fieldName: string): boolean {
    const sensitiveFields = ['password', 'token', 'accessToken', 'refreshToken', 'secret', 'apiKey', 'privateKey', 'logoutPin', 'otp', 'pin'];
    return sensitiveFields.some(field => fieldName.toLowerCase().includes(field.toLowerCase()));
  }

  /**
   * Check if a field contains PII (should be masked)
   */
  private isPiiField(fieldName: string): boolean {
    const piiFields = ['email', 'firstName', 'lastName', 'fullName', 'phone', 'phoneNumber', 'address', 'ssn', 'authorizerId'];
    return piiFields.some(field => fieldName.toLowerCase().includes(field.toLowerCase()));
  }

  /**
   * Mask sensitive value (completely redact)
   */
  private maskSensitiveValue(_fieldName: string, _value: any): string {
    return '[REDACTED]';
  }

  /**
   * Mask PII value (partial mask)
   */
  private maskPiiValue(value: any): string {
    const str = String(value);

    if (!str || str.length === 0) {
      return '[empty]';
    }

    // Email masking
    if (str.includes('@')) {
      return this.maskEmail(str);
    }

    // Name masking (show first 2 chars, mask rest)
    if (str.length <= 3) {
      return '***';
    }
    if (str.length <= 5) {
      return `${str.substring(0, 1)}***`;
    }

    // Show first 2 and last 1 char
    return `${str.substring(0, 2)}***${str.substring(str.length - 1)}`;
  }

  /**
   * Mask email address
   */
  private maskEmail(email: string): string {
    const [localPart, domain] = email.split('@');
    if (!domain) return '***@***';

    if (localPart.length <= 2) {
      return `***@${domain}`;
    }

    return `${localPart.substring(0, 2)}***@${domain}`;
  }
}
