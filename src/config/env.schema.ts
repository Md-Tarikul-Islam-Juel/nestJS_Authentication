import {plainToInstance, Type} from 'class-transformer';
import {IsEnum, IsInt, IsOptional, IsString, Max, Min, ValidateIf, validateSync} from 'class-validator';

type NodeEnvironment = 'development' | 'production' | 'test';
type LogLevel = 'error' | 'warn' | 'info' | 'debug';

const POSTGRES_URL_REGEX = /^postgresql:\/\/.+:.+@.+:\d+\/.+(\?.*)?$/;

export class EnvironmentVariables {
  @IsEnum(['development', 'production', 'test'])
  NODE_ENV: NodeEnvironment = 'development';

  @Type(() => Number)
  @IsInt()
  @Min(0)
  @Max(65535)
  PORT = 3000;

  @IsOptional()
  @IsString()
  DATABASE_URL?: string;

  @ValidateIf(env => !env.DATABASE_URL)
  @IsString()
  DATABASE_HOST: string = 'localhost';

  @ValidateIf(env => !env.DATABASE_URL)
  @IsString()
  DATABASE_USER: string = 'postgres';

  @ValidateIf(env => !env.DATABASE_URL)
  @IsOptional()
  @IsString()
  DATABASE_PASSWORD: string = '';

  @ValidateIf(env => !env.DATABASE_URL)
  @Type(() => Number)
  @IsInt()
  @Min(0)
  @Max(65535)
  DATABASE_PORT: number = 5432;

  @ValidateIf(env => !env.DATABASE_URL)
  @IsString()
  DATABASE_NAME: string = 'postgres';

  @IsString()
  DATABASE_SCHEMA: string = 'public';

  @IsString()
  REDIS_HOST: string = 'localhost';

  @Type(() => Number)
  @IsInt()
  @Min(0)
  @Max(65535)
  REDIS_PORT: number = 6379;

  @IsEnum(['error', 'warn', 'info', 'debug'])
  LOG_LEVEL: LogLevel = 'info';

  @IsOptional()
  @IsString()
  CORS_ALLOWED_ORIGINS?: string;

  @IsOptional()
  @IsString()
  CORS_ALLOWED_ORIGIN_REGEX?: string;

  @IsOptional()
  @IsString()
  CORS_ALLOW_ORIGIN_WILDCARD?: string;

  @IsOptional()
  @IsString()
  CORS_ALLOW_CREDENTIALS?: string;

  @IsOptional()
  @IsString()
  CORS_ALLOWED_METHODS?: string;

  @IsOptional()
  @IsString()
  CORS_ALLOWED_HEADERS?: string;

  @IsOptional()
  @IsString()
  API_VERSIONING_ENABLED?: string;

  @IsOptional()
  @IsString()
  API_VERSIONING_TYPE?: string;

  @IsOptional()
  @IsString()
  API_DEFAULT_VERSION?: string;

  @IsOptional()
  @IsString()
  API_VERSION_HEADER_NAME?: string;

  @IsOptional()
  @IsString()
  API_VERSION_MEDIA_TYPE_KEY?: string;
}

export function validateEnv(config: Record<string, unknown>): EnvironmentVariables {
  const validatedConfig = plainToInstance(EnvironmentVariables, config, {
    enableImplicitConversion: true
  });

  const errors = validateSync(validatedConfig, {
    skipMissingProperties: false
  });

  if (errors.length > 0) {
    const messages = errors
      .map(error => Object.values(error.constraints ?? {}).join(', '))
      .filter(Boolean)
      .join('; ');
    throw new Error(messages);
  }

  if (!validatedConfig.DATABASE_URL && !validatedConfig.DATABASE_HOST) {
    throw new Error('Either DATABASE_URL or DATABASE_HOST must be provided');
  }

  if (validatedConfig.DATABASE_URL && !validatedConfig.DATABASE_URL.includes('${') && !POSTGRES_URL_REGEX.test(validatedConfig.DATABASE_URL)) {
    throw new Error(
      'DATABASE_URL must be a valid PostgreSQL connection string (e.g., postgresql://user:password@host:port/database) or contain environment variable placeholders'
    );
  }

  return validatedConfig;
}
