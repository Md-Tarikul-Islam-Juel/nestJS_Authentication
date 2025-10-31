import {ValidationPipe as NestValidationPipe, ValidationPipeOptions} from '@nestjs/common';

export const validationPipeOptions: ValidationPipeOptions = {
  whitelist: true,
  forbidNonWhitelisted: true,
  transform: true,
  transformOptions: {
    enableImplicitConversion: true
  }
};

export const GlobalValidationPipe = new NestValidationPipe(validationPipeOptions);
