// import { Injectable } from '@nestjs/common';
// import { createLogger, transports, format } from 'winston';
// import { ConfigService } from '@nestjs/config';

// @Injectable()
// export class LoggerService {
//   private logger;

//   constructor(private configService: ConfigService) {
//     this.logger = createLogger({
//       level: this.configService.get('LOG_LEVEL') || 'info',
//       format: format.combine(
//         format.colorize(),
//         format.timestamp(),
//         format.printf(({ timestamp, level, message, context }) => {
//           const contextString = context ? `[${context}] ` : '';
//           return `${timestamp} [${level}] ${contextString}${message}`;
//         }),
//       ),
//       transports: [
//         new transports.Console(),
//         new transports.File({ filename: 'error.log', level: 'error' }),
//         new transports.File({ filename: 'combined.log' }),
//       ],
//     });
//   }

//   info(message: string, context?: string) {
//     this.logger.info(message, { context });
//   }

//   error(message: string, context?: string) {
//     this.logger.error(message, { context });
//   }

//   warn(message: string, context?: string) {
//     this.logger.warn(message, { context });
//   }
// }

import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as moment from 'moment-timezone';
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
        // format.align(),
        // format.metadata(),
        // format.errors(),
        format.printf(({ timestamp, level, message, context }) => {
          const contextString = context ? `[${context}] ` : '';
          return `${timestamp} [${level}] ${contextString}${message}`;
        }),
      ),
      transports: [
        new transports.Console(),
        new transports.File({ filename: 'error.log', level: 'error' }),
        new transports.File({ filename: 'combined.log' }),
      ],
    });
  }

  // Log an information message
  info(message: string, context?: string) {
    this.logger.info(message, { context });
  }

  // Log an error message
  error(message: string, context?: string) {
    this.logger.error(message, { context });
  }

  // Log a warning message
  warn(message: string, context?: string) {
    this.logger.warn(message, { context });
  }
}
