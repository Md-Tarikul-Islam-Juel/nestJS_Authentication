/**
 * Logger Port
 * Domain layer interface for logging operations
 * Following Clean Architecture: application layer depends on domain abstractions
 */
export interface LoggerPort {
  /**
   * Log debug message
   */
  debug(message: string, context?: string, ...args: any[]): void;

  /**
   * Log info message (standard NestJS format)
   */
  log(message: string, context?: string, ...args: any[]): void;

  /**
   * Log info message
   * Supports both string and object format: info({message: string, details?: any})
   */
  info(message: string | object, context?: string, details?: any): void;

  /**
   * Log warning message
   * Supports both NestJS standard: warn(message, context)
   * and extended format: warn(message, context, stack, details)
   */
  warn(message: string | object, context?: string, stack?: string | any, details?: any): void;

  /**
   * Log error message
   * Supports both NestJS standard: error(message, context, stack)
   * and extended format: error(message, context, stack, details)
   */
  error(message: string | object, context?: string, stack?: string | any, details?: any): void;

  /**
   * Log verbose message
   */
  verbose(message: string, context?: string, ...args: any[]): void;
}
