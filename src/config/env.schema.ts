import * as Joi from 'joi';

export const envSchema = Joi.object({
  NODE_ENV: Joi.string().valid('development', 'production', 'test').default('development'),
  PORT: Joi.number().default(3000),
  // DATABASE_URL can be either:
  // 1. A valid PostgreSQL connection string
  // 2. A string with ${} placeholders (will be constructed from individual components)
  DATABASE_URL: Joi.string()
    .custom((value, helpers) => {
      // If it contains ${}, it's a template - allow it
      if (value && value.includes('${')) {
        return value;
      }
      // Otherwise, validate it's a proper PostgreSQL connection string
      if (value && !/^postgresql:\/\/.+:.+@.+:\d+\/.+(\?.*)?$/.test(value)) {
        return helpers.error('string.pattern.base', {
          pattern: 'postgresql://user:password@host:port/database'
        });
      }
      return value;
    })
    .messages({
      'string.pattern.base':
        'DATABASE_URL must be a valid PostgreSQL connection string (e.g., postgresql://user:password@host:port/database) or contain environment variable placeholders'
    }),
  // Individual database components (used if DATABASE_URL not provided or contains ${})
  DATABASE_HOST: Joi.string().default('localhost'),
  DATABASE_USER: Joi.string().default('postgres'),
  DATABASE_PASSWORD: Joi.string().allow('').default(''),
  DATABASE_PORT: Joi.number().default(5432),
  DATABASE_NAME: Joi.string().default('postgres'),
  DATABASE_SCHEMA: Joi.string().default('public'),
  REDIS_HOST: Joi.string().default('localhost'),
  REDIS_PORT: Joi.number().default(6379),
  LOG_LEVEL: Joi.string().valid('error', 'warn', 'info', 'debug').default('info')
}).or('DATABASE_URL', 'DATABASE_HOST'); // Either DATABASE_URL or DATABASE_HOST must be provided
