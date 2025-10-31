import {
  ArgumentsHost,
  BadRequestException,
  Catch,
  ConflictException,
  ExceptionFilter,
  ForbiddenException,
  HttpException,
  HttpStatus,
  Injectable,
  NotFoundException,
  UnauthorizedException
} from '@nestjs/common';
import {GqlArgumentsHost} from '@nestjs/graphql';
import {Prisma} from '@prisma/client';
import {PrismaClientInitializationError} from '@prisma/client/runtime/library';
import {Request} from 'express';
import {DomainError} from '../../errors/domain-error';
import {LoggerService} from '../../observability/logger.service';

@Catch()
@Injectable()
export class ProblemDetailsFilter implements ExceptionFilter {
  constructor(private readonly logger: LoggerService) {}

  catch(exception: unknown, host: ArgumentsHost) {
    const contextType = host.getType();
    const isHttp = contextType === 'http';

    // Only create GQL host if it's actually a GraphQL request
    let response: any;
    let request: Request;

    // Try to determine if it's GraphQL by attempting to create GqlArgumentsHost
    // If it succeeds, it's a GraphQL request; if it throws, it's not
    try {
      const gqlHost = GqlArgumentsHost.create(host);
      const context = gqlHost.getContext();
      response = context?.res || host.switchToHttp().getResponse();
      request = context?.req || host.switchToHttp().getRequest();
    } catch {
      // Not a GraphQL request, use HTTP context directly
      response = host.switchToHttp().getResponse();
      request = host.switchToHttp().getRequest();
    }

    if (exception instanceof DomainError) {
      this.handleDomainError(exception, isHttp, response, request);
      return;
    }

    const status = exception instanceof HttpException ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;
    let message: string | object = exception instanceof HttpException ? exception.getResponse() : 'Internal Server Error';

    if (typeof message === 'object') {
      message = this.extractMessage(message);
    }

    // Enhanced error logging
    const errorDetails: any = {
      path: request.url,
      method: request.method,
      status,
      message: typeof message === 'string' ? message : JSON.stringify(message)
    };

    // Only log request body for POST/PUT/PATCH requests and if it exists
    if (['POST', 'PUT', 'PATCH'].includes(request.method) && request.body) {
      // Sanitize sensitive data from body
      const sanitizedBody = {...request.body};
      if (sanitizedBody.password) {
        sanitizedBody.password = '[REDACTED]';
      }
      errorDetails.body = sanitizedBody;
    }

    this.logger.error(
      {
        message: `Status: ${status}, Message: ${message}`,
        details: errorDetails
      },
      exception instanceof Error ? exception.stack : (exception as any).stack
    );

    if (exception instanceof PrismaClientInitializationError) {
      // Database connection/configuration error
      const errorMessage = exception.message || 'Database connection error';
      this.logger.error({
        message: 'Database initialization error',
        details: {
          error: errorMessage,
          hint: 'Please check your DATABASE_URL environment variable'
        }
      });
      this.handleException(
        isHttp,
        response,
        HttpStatus.SERVICE_UNAVAILABLE,
        'Database connection error. Please check your database configuration.',
        request
      );
    } else if (exception instanceof Prisma.PrismaClientKnownRequestError) {
      this.handlePrismaExceptions(exception, isHttp, response, request);
    } else if (exception instanceof Prisma.PrismaClientValidationError) {
      this.handleException(isHttp, response, HttpStatus.BAD_REQUEST, 'Database validation error', request);
    } else if (exception instanceof BadRequestException) {
      this.handleValidationException(exception, isHttp, response, request);
    } else if (exception instanceof HttpException) {
      this.handleHttpExceptions(exception, isHttp, response, request);
    } else {
      this.handleException(isHttp, response, HttpStatus.INTERNAL_SERVER_ERROR, 'Internal server error', request);
    }
  }

  private handleDomainError(exception: DomainError, isHttp: boolean, response: any, request: Request): void {
    const requestId = (request as any).id || request.headers['x-request-id'] || 'unknown';

    this.logger.error(
      {
        message: `Domain Error: ${exception.message}`,
        details: {
          code: exception.code,
          statusCode: exception.statusCode,
          path: request.url,
          method: request.method,
          requestId
        }
      },
      exception.stack
    );

    if (isHttp) {
      const problemDetails = {
        type: `https://api.example.com/problems/${exception.code.toLowerCase().replace(/_/g, '-')}`,
        title: exception.constructor.name.replace('Error', ''),
        status: exception.statusCode,
        detail: exception.message,
        instance: request.url,
        code: exception.code,
        traceId: requestId
      };

      response.status(exception.statusCode).json(problemDetails);
    } else {
      response.status(exception.statusCode).json({
        errors: [
          {
            message: exception.message,
            code: exception.code,
            statusCode: exception.statusCode
          }
        ]
      });
    }
  }

  private handlePrismaExceptions(exception: Prisma.PrismaClientKnownRequestError, isHttp: boolean, response: any, request?: Request) {
    let message = 'Prisma Client Known Request Error';
    let status = HttpStatus.INTERNAL_SERVER_ERROR;

    switch (exception.code) {
      case 'P2002':
        message = `${exception.meta?.target?.[0] || 'Field'} already exists`;
        status = HttpStatus.CONFLICT;
        break;
      case 'P2025':
        message = "Resource doesn't exist or you don't have permission";
        status = HttpStatus.NOT_FOUND;
        break;
      case 'P2003':
        message = 'Error on deleting the resource';
        status = HttpStatus.BAD_REQUEST;
        break;
      default:
        message = 'Database operation failed';
    }

    this.handleException(isHttp, response, status, message, request);
  }

  private handleHttpExceptions(exception: HttpException, isHttp: boolean, response: any, request?: Request) {
    const status = exception.getStatus();
    const message = exception.message || 'Internal Server Error';

    if (exception instanceof NotFoundException) {
      this.handleException(isHttp, response, status, message, request);
    } else if (exception instanceof BadRequestException) {
      this.handleValidationException(exception, isHttp, response, request);
    } else if (exception instanceof UnauthorizedException) {
      this.handleException(isHttp, response, status, message, request);
    } else if (exception instanceof ForbiddenException) {
      this.handleException(isHttp, response, status, message, request);
    } else if (exception instanceof ConflictException) {
      this.handleException(isHttp, response, status, message, request);
    } else {
      this.handleException(isHttp, response, status, message, request);
    }
  }

  private handleValidationException(exception: BadRequestException, isHttp: boolean, response: any, request?: Request) {
    const status = exception.getStatus();
    const validationResponse = exception.getResponse();

    let message = 'Validation Error';
    if (Array.isArray(validationResponse['message'])) {
      message = validationResponse['message'].join(', ');
    } else if (typeof validationResponse['message'] === 'string') {
      message = validationResponse['message'];
    }

    this.handleException(isHttp, response, status, message, request);
  }

  private handleException(isHttp: boolean, response: any, status: number, message: string, request?: Request) {
    if (isHttp) {
      const requestId = request ? (request as any).id || request.headers['x-request-id'] || 'unknown' : 'unknown';

      // Follow RFC 7807 Problem Details format
      const problemDetails = {
        type: `https://api.example.com/problems/${this.getErrorTypeFromStatus(status)}`,
        title: this.getTitleFromStatus(status),
        status,
        detail: message,
        instance: request?.url || '/',
        traceId: requestId
      };

      response.status(status).json(problemDetails);
    } else {
      response.status(status).json({
        errors: [
          {
            message,
            statusCode: status
          }
        ]
      });
    }
  }

  private getErrorTypeFromStatus(status: number): string {
    if (status >= 400 && status < 500) {
      return 'client-error';
    } else if (status >= 500) {
      return 'server-error';
    }
    return 'unknown-error';
  }

  private getTitleFromStatus(status: number): string {
    const titles: Record<number, string> = {
      400: 'Bad Request',
      401: 'Unauthorized',
      403: 'Forbidden',
      404: 'Not Found',
      409: 'Conflict',
      422: 'Unprocessable Entity',
      429: 'Too Many Requests',
      500: 'Internal Server Error',
      503: 'Service Unavailable'
    };
    return titles[status] || 'Error';
  }

  private extractMessage(message: any): string {
    if (typeof message === 'string') {
      return message;
    }
    if (typeof message.message === 'string') {
      return message.message;
    }
    if (Array.isArray(message.message)) {
      return message.message.join(', ');
    }
    return 'Internal Server Error';
  }
}
