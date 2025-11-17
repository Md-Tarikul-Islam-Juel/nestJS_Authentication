import {CorsOptions} from '@nestjs/common/interfaces/external/cors-options.interface';
import {ConfigService} from '@nestjs/config';
import {LoggerService} from '../observability/logger.service';

const parseList = (value?: string | null): string[] => {
  if (!value) return [];
  return value
    .split(',')
    .map(item => item.trim())
    .filter(Boolean);
};

const buildRegexList = (patterns: string[]): RegExp[] =>
  patterns
    .map(pattern => {
      try {
        return new RegExp(pattern);
      } catch {
        return null;
      }
    })
    .filter((regex): regex is RegExp => Boolean(regex));

export const createCorsOptions = (configService: ConfigService, logger: LoggerService): CorsOptions => {
  const allowCredentials = (configService.get<string>('CORS_ALLOW_CREDENTIALS') ?? 'true').toLowerCase() === 'true';
  const allowedMethods = configService.get<string>('CORS_ALLOWED_METHODS') ?? 'GET,HEAD,PUT,PATCH,POST,DELETE,OPTIONS';
  const allowedHeaders = configService.get<string>('CORS_ALLOWED_HEADERS') ?? 'Authorization,Content-Type,X-Requested-With,X-Internal-Api-Key';

  const staticOrigins = parseList(configService.get<string>('CORS_ALLOWED_ORIGINS')).map(origin => origin.toLowerCase());
  const regexOrigins = buildRegexList(parseList(configService.get<string>('CORS_ALLOWED_ORIGIN_REGEX')));
  const allowAll = (configService.get<string>('CORS_ALLOW_ORIGIN_WILDCARD') ?? 'false').toLowerCase() === 'true';
  const environment = configService.get<string>('NODE_ENV') ?? 'development';

  return {
    origin: (origin, callback) => {
      if (!origin) {
        return callback(null, true);
      }

      const normalizedOrigin = origin.toLowerCase();

      if (allowAll && environment !== 'production') {
        return callback(null, true);
      }

      if (staticOrigins.includes(normalizedOrigin)) {
        return callback(null, true);
      }

      if (regexOrigins.some(regex => regex.test(normalizedOrigin))) {
        return callback(null, true);
      }

      logger.warn(
        {
          message: 'Blocked CORS origin',
          details: {origin: normalizedOrigin}
        },
        'createCorsOptions'
      );
      return callback(new Error('Not allowed by CORS'));
    },
    credentials: allowCredentials,
    methods: allowedMethods,
    allowedHeaders,
    optionsSuccessStatus: 204,
    preflightContinue: false
  };
};
