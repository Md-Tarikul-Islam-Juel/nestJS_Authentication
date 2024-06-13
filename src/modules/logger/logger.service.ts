import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
// import * as moment from 'moment-timezone';
import moment from 'moment-timezone';
import { createLogger, format, transports } from 'winston';

@Injectable()
export class LoggerService {
  private logger;

  constructor(private configService: ConfigService) {
    this.logger = createLogger({
      level: this.configService.get('LOG_LEVEL') || 'info',
      format: format.combine(
        format.json(),
        format.colorize(),
        format.timestamp({
          format: () => moment().tz('UTC').format('YYYY-MM-DD HH:mm:ss Z'),
        }),
        format.printf(({ timestamp, level, message, context, details }) => {
          const contextString = context ? `[${context}] ` : '';
          const detailsString = details ? `Details: ${JSON.stringify(details)}` : '';
          return `${timestamp} [${level}] ${contextString}${message} ${detailsString}`;
        }),
      ),
      transports: [
        new transports.Console(),
        new transports.File({ filename: 'error.log', level: 'error' }),
        new transports.File({ filename: 'combined.log' }),
      ],
    });
  }

  private getMethodName(depth: number = 3): string {
    const stack = new Error().stack;
    const stackLines = stack?.split('\n');
    if (!stackLines || stackLines.length <= depth) {
      return 'UnknownMethod';
    }
    const methodLine = stackLines[depth].trim();
    return methodLine.split(' ')[1];
  }

  private buildContext(depth: number = 3): string {
    return `${this.getMethodName(depth + 1)}()`;
  }

  // Log an information message
  info(log: { message: string, details?: any }, context?: string) {
    const dynamicContext = this.buildContext();
    this.logger.info({ ...log, context: context || dynamicContext });
  }

  // Log an error message
  error(log: { message: string, details?: any }, context?: string) {
    const dynamicContext = this.buildContext();
    this.logger.error({ ...log, context: context || dynamicContext });
  }

  // Log a warning message
  warn(log: { message: string, details?: any }, context?: string) {
    const dynamicContext = this.buildContext();
    this.logger.warn({ ...log, context: context || dynamicContext });
  }
}



