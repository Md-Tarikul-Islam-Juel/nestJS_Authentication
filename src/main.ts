import {ConfigService} from '@nestjs/config';
import {NestFactory} from '@nestjs/core';
import {DocumentBuilder, SwaggerModule} from '@nestjs/swagger';
import {useContainer} from 'class-validator';
import {AppModule} from './app.module';
import {ProblemDetailsFilter} from './common/http/filters/problem-details.filter';
import {GlobalValidationPipe} from './common/http/pipes/validation.pipe';
import {createVersioningConfig, createVersioningOptions} from './common/http/versioning.config';
import {LoggerService} from './common/observability/logger.service';
import {createCorsOptions} from './common/security/cors';
import {securityHeadersMiddleware} from './common/security/helmet';
import {createAdaptiveRateLimiter} from './common/security/rate-limiter';
import {RedisService} from './platform/redis/redis.service';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {abortOnError: false});

  // Configure class-validator to use NestJS DI container
  // This allows custom validators (like PasswordValidator) to inject dependencies
  useContainer(app.select(AppModule), {fallbackOnErrors: true});

  const configService = app.get(ConfigService);
  const logger = app.get(LoggerService);

  // Handle unhandled promise rejections to ensure errors don't hang
  process.on('unhandledRejection', (reason: any) => {
    logger.error('Unhandled Promise Rejection', 'bootstrap()', reason instanceof Error ? reason.stack : undefined, {
      reason: reason instanceof Error ? reason.message : String(reason)
    });
  });

  const redisService = app.get(RedisService);

  app.enableCors(createCorsOptions(configService, logger));
  securityHeadersMiddleware.forEach(middleware => app.use(middleware));

  // Enable API versioning
  const versioningConfig = createVersioningConfig(configService);
  const versioningOptions = createVersioningOptions(versioningConfig);
  if (versioningOptions) {
    app.enableVersioning(versioningOptions);
    logger.info(`API versioning enabled: ${versioningConfig.type} (default: ${versioningConfig.defaultVersion})`, 'bootstrap()');
  }

  app.use(
    '/auth',
    createAdaptiveRateLimiter(redisService, logger, {
      keyPrefix: 'rate-limit:auth',
      windowMs: 60_000,
      maxRequests: 30,
      blockDurationMs: 15 * 60_000,
      blockResponseMessage: 'Too many authentication attempts. Please try again later.'
    })
  );

  // Register global exception filter - MUST be before useGlobalPipes
  app.useGlobalFilters(new ProblemDetailsFilter(logger));

  app.useGlobalPipes(GlobalValidationPipe);

  // Swagger configuration with versioning support
  const swaggerConfig = new DocumentBuilder()
    .setTitle('Authentication Boilerplate')
    .setDescription('NestJS Authentication API with Clean Architecture')
    .setVersion('1.0')
    .addTag('auth')
    .addTag('users');

  // Add API version info if versioning is enabled
  if (versioningConfig.enabled) {
    swaggerConfig.addServer(`/v${versioningConfig.defaultVersion}`, `API Version ${versioningConfig.defaultVersion}`);
  }

  const config = swaggerConfig.build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  const port = configService.get('PORT') || 3000;
  await app.listen(port);
  logger.info(`Application is running on: http://localhost:${port}`, 'bootstrap()');
}

bootstrap();
