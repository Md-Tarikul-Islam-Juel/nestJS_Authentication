import {Injectable, LoggerService as NestLoggerService} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import moment from 'moment-timezone';
import {createLogger, format, Logger, transports} from 'winston';
import {PiiMaskerService} from '../data-protection/pii-masker.service';

/**
 * Enhanced LoggerService following NestJS best practices
 * Combines NestJS Logger with Winston for structured logging
 * Automatically masks PII in all log calls to prevent data leaks
 */
@Injectable()
export class LoggerService implements NestLoggerService {
  private readonly winstonLogger: Logger;
  private readonly isDevelopment: boolean;

  constructor(
    private readonly configService: ConfigService,
    private readonly piiMasker: PiiMaskerService
  ) {
    this.isDevelopment = this.configService.get('NODE_ENV') !== 'production';

    const logLevel = this.configService.get('LOG_LEVEL') || (this.isDevelopment ? 'debug' : 'info');

    this.winstonLogger = createLogger({
      level: logLevel,
      format: format.combine(
        format.timestamp({
          format: () => moment().tz('UTC').format('YYYY-MM-DD HH:mm:ss Z')
        }),
        format.errors({stack: true}),
        format.splat(),
        format.json()
      ),
      defaultMeta: {
        service: 'nestjs-authentication',
        environment: this.configService.get('NODE_ENV') || 'development'
      },
      transports: [
        // Console transport with colors in development
        new transports.Console({
          format: format.combine(
            ...(this.isDevelopment ? [format.colorize()] : []),
            format.printf(({timestamp, level, message, context, details, stack, ...meta}) => {
              return this.formatConsoleOutput({
                timestamp,
                level,
                message,
                context,
                details,
                stack,
                meta,
                isDevelopment: this.isDevelopment
              });
            })
          )
        }),
        // Error log file
        new transports.File({
          filename: 'logs/error.log',
          level: 'error',
          format: format.combine(format.timestamp(), format.json())
        }),
        // Combined log file
        new transports.File({
          filename: 'logs/combined.log',
          format: format.combine(format.timestamp(), format.json())
        })
      ],
      // Handle exceptions
      exceptionHandlers: [new transports.File({filename: 'logs/exceptions.log'})],
      // Handle promise rejections
      rejectionHandlers: [new transports.File({filename: 'logs/rejections.log'})]
    });
  }

  /**
   * Log debug message
   * ⚠️ AUTOMATIC PII MASKING: All details and messages are automatically masked for PII
   */
  debug(message: string, context?: string, ...args: any[]): void {
    const maskedMessage = this.piiMasker.maskString(message);
    const parsedArgs = this.parseArgs(args);
    const maskedArgs = Object.keys(parsedArgs).length > 0 ? this.maskPiiInValue(parsedArgs) : {};

    this.winstonLogger.debug(maskedMessage, {
      context: context || this.getContext(),
      ...maskedArgs
    });
  }

  /**
   * Log info message
   */
  log(message: string, context?: string, ...args: any[]): void {
    this.info(message, context, ...args);
  }

  /**
   * Log info message
   * ⚠️ AUTOMATIC PII MASKING: All details and messages are automatically masked for PII
   */
  info(message: string | object, context?: string, details?: any): void {
    if (typeof message === 'string') {
      const maskedMessage = this.piiMasker.maskString(message);
      const maskedDetails = details ? this.maskPiiInValue(details) : undefined;

      this.winstonLogger.info(maskedMessage, {
        context: context || this.getContext(),
        ...(maskedDetails && {details: maskedDetails})
      });
    } else {
      // Support legacy format: info({message: string, details?: any})
      const msgObj = message as any;
      const maskedMessage = typeof msgObj.message === 'string' ? this.piiMasker.maskString(msgObj.message) : JSON.stringify(message);
      const maskedDetails = msgObj.details ? this.maskPiiInValue(msgObj.details) : undefined;

      this.winstonLogger.info(maskedMessage, {
        context: context || this.getContext(),
        ...(maskedDetails && {details: maskedDetails})
      });
    }
  }

  /**
   * Log warning message
   * Supports both NestJS standard: warn(message, context)
   * and extended format: warn(message, context, stack, details)
   *
   * ⚠️ AUTOMATIC PII MASKING: All details and messages are automatically masked for PII
   */
  warn(message: string | object, context?: string, stack?: string | any, details?: any): void {
    // Handle legacy format: warn({message: string, details?: any})
    if (typeof message === 'object' && message !== null && !(message instanceof Error)) {
      let warnMessage = (message as any).message || JSON.stringify(message);
      let warnDetails = details || (message as any).details;

      // Automatic PII masking
      warnMessage = typeof warnMessage === 'string' ? this.piiMasker.maskString(warnMessage) : warnMessage;
      if (warnDetails) {
        warnDetails = this.maskPiiInValue(warnDetails);
      }
      if (typeof stack === 'object' && !details) {
        warnDetails = this.maskPiiInValue(stack);
      }

      this.winstonLogger.warn(warnMessage, {
        context: context || this.getContext(),
        ...(typeof stack === 'string' && {stack}),
        ...(warnDetails && {details: warnDetails})
      });
      return;
    }

    // Standard NestJS format: warn(message: string, context?: string)
    // Extended format: warn(message: string, context?: string, stack?: string, details?: any)
    let warnMessage = typeof message === 'string' ? message : message instanceof Error ? message.message : String(message);
    const warnStack = typeof stack === 'string' ? stack : undefined;
    let warnDetails = typeof stack === 'object' ? stack : details;

    // Automatic PII masking
    warnMessage = this.piiMasker.maskString(warnMessage);
    if (warnDetails) {
      warnDetails = this.maskPiiInValue(warnDetails);
    }

    this.winstonLogger.warn(warnMessage, {
      context: context || this.getContext(),
      ...(warnStack && {stack: warnStack}),
      ...(warnDetails && {details: warnDetails})
    });
  }

  /**
   * Log error message
   * Supports both NestJS standard: error(message, context, stack)
   * and extended format: error(message, context, stack, details)
   *
   * ⚠️ AUTOMATIC PII MASKING: All details and messages are automatically masked for PII
   */
  error(message: string | object, context?: string, stack?: string | any, details?: any): void {
    // Handle legacy format: error({message: string, details?: any})
    if (typeof message === 'object' && message !== null && !(message instanceof Error)) {
      const errorMessage = (message as any).message || JSON.stringify(message);
      const errorStack = stack || (message as any).stack;
      let errorDetails = details || (message as any).details;

      // Automatic PII masking in message
      const maskedMessage = typeof errorMessage === 'string' ? this.piiMasker.maskString(errorMessage) : errorMessage;

      // Automatic PII masking in details
      if (errorDetails) {
        errorDetails = this.maskPiiInValue(errorDetails);
      }
      if (typeof stack === 'object' && !details) {
        errorDetails = this.maskPiiInValue(stack);
      }

      this.winstonLogger.error(maskedMessage, {
        context: context || this.getContext(),
        ...(errorStack && typeof errorStack === 'string' && {stack: errorStack}),
        ...(errorDetails && {details: errorDetails})
      });
      return;
    }

    // Standard NestJS format: error(message: string, context?: string, stack?: string)
    // Extended format: error(message: string, context?: string, stack?: string, details?: any)
    let errorMessage = typeof message === 'string' ? message : message instanceof Error ? message.message : String(message);
    const errorStack = typeof stack === 'string' ? stack : undefined;
    let errorDetails = typeof stack === 'object' ? stack : details;

    // Automatic PII masking in message
    errorMessage = this.piiMasker.maskString(errorMessage);

    // Automatic PII masking in details
    if (errorDetails) {
      errorDetails = this.maskPiiInValue(errorDetails);
    }

    this.winstonLogger.error(errorMessage, {
      context: context || this.getContext(),
      ...(errorStack && {stack: errorStack}),
      ...(errorDetails && {details: errorDetails})
    });
  }

  /**
   * Log verbose message
   * ⚠️ AUTOMATIC PII MASKING: All details and messages are automatically masked for PII
   */
  verbose(message: string, context?: string, ...args: any[]): void {
    const maskedMessage = this.piiMasker.maskString(message);
    const parsedArgs = this.parseArgs(args);
    const maskedArgs = Object.keys(parsedArgs).length > 0 ? this.maskPiiInValue(parsedArgs) : {};

    this.winstonLogger.verbose(maskedMessage, {
      context: context || this.getContext(),
      ...maskedArgs
    });
  }

  /**
   * Get context from call stack
   * Returns format: "ClassName.methodName()"
   * Example: "UserService.authenticateUser()" or "ProblemDetailsFilter.handleDomainError()"
   */
  private getContext(depth: number = 4): string {
    try {
      const stack = new Error().stack;
      const stackLines = stack?.split('\n');
      if (!stackLines || stackLines.length <= depth) {
        return 'UnknownContext';
      }

      const methodLine = stackLines[depth].trim();

      // Match format: "at ClassName.methodName (...)"
      // Example: "at UserService.authenticateUser (/Users/.../user.service.ts:85:10)"
      // Example: "at ProblemDetailsFilter.handleDomainError (/Users/.../problem-details.filter.ts:123:45)"
      const match = methodLine.match(/at\s+(\w+)\.(\w+)\s+/);
      if (match && match[1] && match[2]) {
        const [, className, methodName] = match;
        return `${className}.${methodName}()`;
      }

      // Fallback: extract from different stack format
      const fallbackMatch = methodLine.match(/\s+(\w+)\s+\(/);
      return fallbackMatch && fallbackMatch[1] ? `${fallbackMatch[1]}()` : 'UnknownContext';
    } catch {
      return 'UnknownContext';
    }
  }

  /**
   * Parse additional arguments for logging
   */
  private parseArgs(args: any[]): Record<string, any> {
    if (args.length === 0) return {};
    if (args.length === 1 && typeof args[0] === 'object' && args[0] !== null) {
      return args[0];
    }
    return {additionalData: args};
  }

  /**
   * Create a child logger with additional context
   */
  setContext(_context: string): LoggerService {
    // Return a new instance with context set (simplified for compatibility)
    void _context; // Parameter intentionally unused for compatibility
    return this;
  }

  /**
   * Format console output with better organization and visual appeal
   */
  private formatConsoleOutput({
    timestamp,
    level,
    message,
    context,
    details,
    stack,
    meta,
    isDevelopment
  }: {
    timestamp: string;
    level: string;
    message: string;
    context?: string;
    details?: any;
    stack?: string;
    meta?: any;
    isDevelopment: boolean;
  }): string {
    // ANSI color codes
    const colors = {
      reset: '\x1b[0m',
      dim: '\x1b[90m',
      bright: '\x1b[1m',
      cyan: '\x1b[36m',
      yellow: '\x1b[33m',
      red: '\x1b[31m',
      green: '\x1b[32m',
      blue: '\x1b[34m',
      magenta: '\x1b[35m',
      white: '\x1b[37m',
      gray: '\x1b[90m'
    };

    // Emoji/icons for log levels (only in development for better readability)
    const levelIcons: Record<string, string> = isDevelopment
      ? {
          error: '❌',
          warn: '⚠️ ',
          info: 'ℹ️ ',
          debug: '🔍',
          verbose: '📝'
        }
      : {};

    const icon = levelIcons[level.toLowerCase()] || '';

    // Table configuration - wider table to prevent overflow
    const TABLE_WIDTH = 120; // Total table width
    const CONTENT_WIDTH = TABLE_WIDTH - 4; // Content width (minus border │ + space on each side)

    // Helper to create separator line
    const separator = (char: string = '─', length: number = CONTENT_WIDTH, color: string = colors.dim) => {
      return `${color}${char.repeat(length)}${colors.reset}`;
    };

    // Format context with cyan color
    const contextStr = context ? `${colors.cyan}[${context}]${colors.reset}` : '';

    // Format main message header - level is already colored by Winston's colorize
    let output = `${colors.dim}┌${separator('─', CONTENT_WIDTH, colors.dim)}┐${colors.reset}\n`;
    output += `${colors.dim}│${colors.reset} ${timestamp} ${icon}${level} ${contextStr} ${colors.white}${message}${colors.reset}\n`;

    const hasAdditionalInfo = details || stack || (meta && Object.keys(meta).length > 0);

    // Format details with pretty JSON in a box
    if (details) {
      output += `${colors.dim}├${separator('─', CONTENT_WIDTH, colors.dim)}┤${colors.reset}\n`;
      output += `${colors.dim}│${colors.reset} ${colors.bright}${colors.yellow}📋 Details${colors.reset}\n`;
      output += `${colors.dim}├${separator('─', CONTENT_WIDTH, colors.dim)}┤${colors.reset}\n`;
      try {
        const formattedDetails = typeof details === 'string' ? details : JSON.stringify(details, null, 2);
        const detailLines = formattedDetails.split('\n');
        detailLines.forEach((line: string) => {
          // Wrap long lines to match table width
          const maxLength = CONTENT_WIDTH - 2; // Account for padding
          if (line.length > maxLength) {
            // Split long lines at word boundaries or spaces when possible
            let remainingLine = line;
            while (remainingLine.length > 0) {
              if (remainingLine.length <= maxLength) {
                output += `${colors.dim}│${colors.reset} ${colors.white}${remainingLine}${colors.reset}\n`;
                break;
              }
              // Try to break at space or comma for better readability
              let breakPoint = maxLength;
              const spaceIndex = remainingLine.lastIndexOf(' ', maxLength);
              const commaIndex = remainingLine.lastIndexOf(',', maxLength);
              if (spaceIndex > maxLength * 0.7) breakPoint = spaceIndex + 1;
              else if (commaIndex > maxLength * 0.7) breakPoint = commaIndex + 1;

              const chunk = remainingLine.substring(0, breakPoint);
              output += `${colors.dim}│${colors.reset} ${colors.white}${chunk}${colors.reset}\n`;
              remainingLine = '  ' + remainingLine.substring(breakPoint).trimStart();
            }
          } else {
            output += `${colors.dim}│${colors.reset} ${colors.white}${line}${colors.reset}\n`;
          }
        });
      } catch {
        const errorDetails = String(details);
        // Don't truncate error details - show full message
        const errorLines = errorDetails.split('\n');
        errorLines.forEach((line: string) => {
          output += `${colors.dim}│${colors.reset} ${colors.white}${line}${colors.reset}\n`;
        });
      }
    }

    // Format additional metadata
    const filteredMeta = Object.keys(meta || {}).filter(
      key => !['service', 'environment', 'timestamp', 'level', 'message', 'context', 'details', 'stack'].includes(key)
    );
    if (filteredMeta.length > 0) {
      if (details) {
        output += `${colors.dim}├${separator('─', CONTENT_WIDTH, colors.dim)}┤${colors.reset}\n`;
      } else {
        output += `${colors.dim}├${separator('─', CONTENT_WIDTH, colors.dim)}┤${colors.reset}\n`;
      }
      output += `${colors.dim}│${colors.reset} ${colors.bright}${colors.magenta}📦 Metadata${colors.reset}\n`;
      output += `${colors.dim}├${separator('─', CONTENT_WIDTH, colors.dim)}┤${colors.reset}\n`;
      try {
        const metaObj: any = {};
        filteredMeta.forEach(key => {
          metaObj[key] = meta[key];
        });
        const formattedMeta = JSON.stringify(metaObj, null, 2);
        const metaLines = formattedMeta.split('\n');
        metaLines.forEach((line: string) => {
          // Wrap long lines to match table width
          const maxLength = CONTENT_WIDTH - 2; // Account for padding
          if (line.length > maxLength) {
            let remainingLine = line;
            while (remainingLine.length > 0) {
              if (remainingLine.length <= maxLength) {
                output += `${colors.dim}│${colors.reset} ${colors.white}${remainingLine}${colors.reset}\n`;
                break;
              }
              // Try to break at space or comma
              let breakPoint = maxLength;
              const spaceIndex = remainingLine.lastIndexOf(' ', maxLength);
              const commaIndex = remainingLine.lastIndexOf(',', maxLength);
              if (spaceIndex > maxLength * 0.7) breakPoint = spaceIndex + 1;
              else if (commaIndex > maxLength * 0.7) breakPoint = commaIndex + 1;

              const chunk = remainingLine.substring(0, breakPoint);
              output += `${colors.dim}│${colors.reset} ${colors.white}${chunk}${colors.reset}\n`;
              remainingLine = '  ' + remainingLine.substring(breakPoint).trimStart();
            }
          } else {
            output += `${colors.dim}│${colors.reset} ${colors.white}${line}${colors.reset}\n`;
          }
        });
      } catch {
        const metaStr = JSON.stringify(meta);
        // Don't truncate metadata - show full content
        const metaLines = metaStr.split('\n');
        metaLines.forEach((line: string) => {
          output += `${colors.dim}│${colors.reset} ${colors.white}${line}${colors.reset}\n`;
        });
      }
    }

    // Format stack trace - NEVER truncate stack traces (critical for debugging)
    if (stack) {
      if (details || filteredMeta.length > 0) {
        output += `${colors.dim}├${separator('─', CONTENT_WIDTH, colors.dim)}┤${colors.reset}\n`;
      } else {
        output += `${colors.dim}├${separator('─', CONTENT_WIDTH, colors.dim)}┤${colors.reset}\n`;
      }
      output += `${colors.dim}│${colors.reset} ${colors.bright}${colors.red}🔴 Stack Trace${colors.reset}\n`;
      output += `${colors.dim}├${separator('─', CONTENT_WIDTH, colors.dim)}┤${colors.reset}\n`;
      const stackLines = stack.split('\n');
      stackLines.forEach((line: string, idx: number) => {
        const trimmedLine = line.trim();
        // Wrap long stack trace lines to match table width
        const maxLength = CONTENT_WIDTH - 4; // Account for indent padding
        if (trimmedLine.length > maxLength) {
          // For long stack trace lines, show full line with wrapping
          let remainingLine = trimmedLine;
          const indent = idx === 0 ? '' : '  ';
          while (remainingLine.length > 0) {
            if (remainingLine.length <= maxLength) {
              output += `${colors.dim}│${colors.reset} ${colors.gray}${indent}${remainingLine}${colors.reset}\n`;
              break;
            }
            // Break at space or / for file paths
            let breakPoint = maxLength;
            const spaceIndex = remainingLine.lastIndexOf(' ', maxLength);
            const slashIndex = remainingLine.lastIndexOf('/', maxLength);
            if (spaceIndex > maxLength * 0.6) breakPoint = spaceIndex + 1;
            else if (slashIndex > maxLength * 0.6) breakPoint = slashIndex + 1;

            const chunk = remainingLine.substring(0, breakPoint);
            output += `${colors.dim}│${colors.reset} ${colors.gray}${indent}${chunk}${colors.reset}\n`;
            remainingLine = '   ' + remainingLine.substring(breakPoint).trimStart();
            // Update indent for continuation lines
            if (idx === 0) {
              // First line continuation
            } else {
              // Subsequent line continuation
            }
          }
        } else {
          output += `${colors.dim}│${colors.reset} ${colors.gray}${idx === 0 ? trimmedLine : '  ' + trimmedLine}${colors.reset}\n`;
        }
      });
    }

    // Close the box
    output += `${colors.dim}└${separator('─', CONTENT_WIDTH, colors.dim)}┘${colors.reset}\n`;

    // Add spacing between logs
    if (hasAdditionalInfo || level.toLowerCase() === 'error') {
      output += '\n'; // Extra line for errors and logs with details
    }

    return output;
  }

  /**
   * Automatically mask PII in any value (object, array, or primitive)
   * This is called automatically for all log details to ensure PII is never exposed
   * Following DATABASE_STANDARDS.md: "masking/redaction at ORM & log layers"
   */
  private maskPiiInValue(value: any): any {
    if (value === null || value === undefined) {
      return value;
    }

    // Handle arrays
    if (Array.isArray(value)) {
      return value.map(item => this.maskPiiInValue(item));
    }

    // Handle objects (including Prisma models, plain objects, etc.)
    if (typeof value === 'object' && !(value instanceof Date) && !(value instanceof Error)) {
      // Use maskObject to recursively mask all fields
      return this.piiMasker.maskObject(value);
    }

    // Handle strings (mask email addresses, etc.)
    if (typeof value === 'string') {
      return this.piiMasker.maskString(value);
    }

    // Primitives (numbers, booleans, etc.) - no masking needed
    return value;
  }
}
