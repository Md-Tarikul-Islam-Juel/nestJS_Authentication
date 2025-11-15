import {Injectable} from '@nestjs/common';
import {LoggerService} from '../../../../common/observability/logger.service';
import {LoggerPort} from '../../domain/repositories/logger.port';

/**
 * Logger Adapter
 * Infrastructure adapter implementing LoggerPort
 * Uses LoggerService from common/observability for logging operations
 */
@Injectable()
export class LoggerAdapter implements LoggerPort {
  constructor(private readonly loggerService: LoggerService) {}

  debug(message: string, context?: string, ...args: any[]): void {
    this.loggerService.debug(message, context, ...args);
  }

  log(message: string, context?: string, ...args: any[]): void {
    this.loggerService.log(message, context, ...args);
  }

  info(message: string | object, context?: string, details?: any): void {
    this.loggerService.info(message, context, details);
  }

  warn(message: string | object, context?: string, stack?: string | any, details?: any): void {
    this.loggerService.warn(message, context, stack, details);
  }

  error(message: string | object, context?: string, stack?: string | any, details?: any): void {
    this.loggerService.error(message, context, stack, details);
  }

  verbose(message: string, context?: string, ...args: any[]): void {
    this.loggerService.verbose(message, context, ...args);
  }
}

