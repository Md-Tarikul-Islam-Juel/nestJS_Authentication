import { NestFactory } from '@nestjs/core';
// import { rateLimit } from 'express-rate-limit';
import { AppModule } from './app.module';
import { AllExceptionsFilter } from './filters/all-exceptions.filter';
import { JoiValidationExceptionFilter } from './filters/joi-exception.filter';

// const limiter = rateLimit({
//   //from per ip we allow max 5/min
//   windowMs: 1000 * 60 * 1, // 1 minutes
//   max: 50, // Maximum 5 requests per IP in 15 minutes
//   message: 'Too many requests, please try again later.',
// });

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalFilters(new AllExceptionsFilter());
  app.useGlobalFilters(new JoiValidationExceptionFilter());
  // app.use('/auth', limiter); // Apply rate limiting to authentication rou
  // app.use('/user', limiter); // Apply rate limiting to user route

  await app.listen(3000);
}
bootstrap();
