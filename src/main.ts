import {ConfigService} from '@nestjs/config';
import {NestFactory} from '@nestjs/core';
import {DocumentBuilder, SwaggerModule} from '@nestjs/swagger';
import {AppModule} from './app.module';
import {ProblemDetailsFilter} from './common/http/filters/problem-details.filter';
import {GlobalValidationPipe} from './common/http/pipes/validation.pipe';
import {LoggerService} from './common/observability/logger.service';
import {corsOptions} from './common/security/cors';
import {helmetConfig} from './common/security/helmet';
import {rateLimiterConfig} from './common/security/rate-limiter';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {abortOnError: false});

  const configService = app.get(ConfigService);
  const logger = app.get(LoggerService);

  // Handle unhandled promise rejections to ensure errors don't hang
  process.on('unhandledRejection', (reason: any) => {
    logger.error('Unhandled Promise Rejection', 'bootstrap()', reason instanceof Error ? reason.stack : undefined, {
      reason: reason instanceof Error ? reason.message : String(reason)
    });
  });

  app.enableCors(corsOptions);
  app.use(helmetConfig);
  app.use('/auth', rateLimiterConfig);

  // Register global exception filter - MUST be before useGlobalPipes
  app.useGlobalFilters(new ProblemDetailsFilter(logger));

  app.useGlobalPipes(GlobalValidationPipe);

  const config = new DocumentBuilder()
    .setTitle('Authentication Boilerplate')
    .setDescription('NestJS Authentication API with Clean Architecture')
    .setVersion('1.0')
    .addTag('auth')
    .addTag('users')
    .build();
  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api', app, document);

  const port = configService.get('PORT') || 3000;
  await app.listen(port);
  logger.info(`Application is running on: http://localhost:${port}`, 'bootstrap()');
}

bootstrap();
