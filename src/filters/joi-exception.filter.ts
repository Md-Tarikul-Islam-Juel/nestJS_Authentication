import { ArgumentsHost, Catch, ExceptionFilter } from '@nestjs/common';
import * as Joi from 'joi';

@Catch(Joi.ValidationError)
export class JoiValidationExceptionFilter implements ExceptionFilter {
  catch(exception: Joi.ValidationError, host: ArgumentsHost) {
    const ctx = host.switchToHttp();
    const response = ctx.getResponse();
    const status = 200; // Bad Request
    const errorMessage =
      'Validation failed: ' +
      exception.details.map((error) => error.message).join(', ');

    response.status(status).json({
      success: false,
      message: errorMessage,
    });
  }
}
