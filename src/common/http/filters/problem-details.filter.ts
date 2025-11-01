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

    try {
      // Try to determine if it's GraphQL by attempting to create GqlArgumentsHost
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

      // Validate response exists
      if (!response) {
        this.logger.error('CRITICAL: No response object available in exception filter', 'ProblemDetailsFilter.catch()', undefined, {
          contextType,
          isHttp
        });
        return;
      }

      // Check if headers already sent
      if (isHttp && response.headersSent) {
        this.logger.warn('Response headers already sent, cannot send error response', 'ProblemDetailsFilter.catch()', undefined, {
          path: request?.url
        } as any);
        return;
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
        `Status: ${status}, Message: ${message}`,
        'ProblemDetailsFilter.catch()',
        exception instanceof Error ? exception.stack : (exception as any).stack,
        errorDetails
      );

      if (exception instanceof PrismaClientInitializationError) {
        // Database connection/configuration error
        const errorMessage = exception.message || 'Database connection error';
        this.logger.error('Database initialization error', 'ProblemDetailsFilter.catch()', undefined, {
          error: errorMessage,
          hint: 'Please check your DATABASE_URL environment variable'
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
    } catch (filterError) {
      // Critical: If exception filter itself fails, try to send a basic response
      this.logger.error(
        'CRITICAL: Exception filter failed',
        'ProblemDetailsFilter.catch()',
        filterError instanceof Error ? filterError.stack : undefined,
        {
          error: filterError instanceof Error ? filterError.message : String(filterError),
          originalException: exception instanceof Error ? exception.message : String(exception)
        }
      );

      // Try to get response and send error
      try {
        const httpResponse = host.switchToHttp().getResponse();
        if (httpResponse && !httpResponse.headersSent) {
          httpResponse.status(500).json({
            success: false,
            message: 'An unexpected error occurred'
          });
        }
      } catch (finalError) {
        // Last resort - log and give up
        this.logger.error(
          'ABSOLUTE FAILURE: Cannot send any error response',
          'ProblemDetailsFilter.catch()',
          finalError instanceof Error ? finalError.stack : undefined,
          {
            error: finalError instanceof Error ? finalError.message : String(finalError)
          }
        );
      }
    }
  }

  private handleDomainError(exception: DomainError, isHttp: boolean, response: any, request: Request): void {
    const requestId = (request as any).id || request.headers['x-request-id'] || 'unknown';

    this.logger.error(`Domain Error: ${exception.message}`, 'ProblemDetailsFilter.handleDomainError()', exception.stack, {
      code: exception.code,
      statusCode: exception.statusCode,
      path: request.url,
      method: request.method,
      requestId
    });

    if (isHttp) {
      // Double-check headers haven't been sent
      if (response.headersSent) {
        this.logger.warn('Cannot send domain error - headers already sent', 'ProblemDetailsFilter.handleDomainError()', undefined, {
          path: request.url
        } as any);
        return;
      }

      // Check if it's an auth endpoint - return BaseResponseDto format
      const isAuthEndpoint = request.url?.includes('/auth/');
      let errorMessage = exception.message;

      // Customize message for change password endpoint
      if (request.url?.includes('/auth/change-password')) {
        if (exception.code === 'INVALID_CREDENTIALS') {
          errorMessage = 'Failed to change password';
        }
      }

      try {
        if (isAuthEndpoint) {
          // Return BaseResponseDto format for auth endpoints
          const responseBody = {
            success: false,
            message: errorMessage
          };

          this.logger.debug('About to send auth error response', 'ProblemDetailsFilter.handleDomainError()', undefined, {
            statusCode: exception.statusCode,
            responseBody,
            headersSent: response.headersSent
          });

          // CRITICAL: Ensure response is sent
          try {
            response.status(exception.statusCode);
            response.setHeader('Content-Type', 'application/json');
            response.json(responseBody);
          } catch (jsonError) {
            // Fallback: Try using send() method
            this.logger.error(
              'CRITICAL: json() failed, using fallback send()',
              'ProblemDetailsFilter.handleDomainError()',
              jsonError instanceof Error ? jsonError.stack : undefined,
              {
                error: jsonError instanceof Error ? jsonError.message : String(jsonError),
                hasStatus: typeof response.status === 'function',
                hasJson: typeof response.json === 'function',
                hasSend: typeof response.send === 'function'
              }
            );

            // Fallback to text response
            if (typeof response.status === 'function' && typeof response.send === 'function') {
              response.status(exception.statusCode).setHeader('Content-Type', 'application/json').send(JSON.stringify(responseBody));
            }
          }
        } else {
          // Return RFC 7807 Problem Details format for other endpoints
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
        }
      } catch (sendError) {
        this.logger.error({
          message: 'CRITICAL: Failed to send domain error response',
          details: {
            error: sendError instanceof Error ? sendError.message : String(sendError),
            path: request.url,
            stack: sendError instanceof Error ? sendError.stack : undefined
          }
        });
      }
    } else {
      // GraphQL error response
      try {
        if (!response.headersSent) {
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
      } catch (sendError) {
        this.logger.error({
          message: 'Failed to send GraphQL error response',
          details: {
            error: sendError instanceof Error ? sendError.message : String(sendError)
          }
        });
      }
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
    // Validate response exists
    if (!response) {
      this.logger.error({
        message: 'Cannot handle exception - no response object',
        details: {status, message}
      });
      return;
    }

    // Check if headers already sent
    if (isHttp && response.headersSent) {
      this.logger.warn({
        message: 'Cannot send exception response - headers already sent',
        details: {status, message, path: request?.url}
      });
      return;
    }

    try {
      if (isHttp) {
        const requestId = request ? (request as any).id || request.headers['x-request-id'] || 'unknown' : 'unknown';

        // Check if it's an auth endpoint - return BaseResponseDto format
        const isAuthEndpoint = request?.url?.includes('/auth/');

        if (isAuthEndpoint) {
          // Return BaseResponseDto format for auth endpoints
          const responseBody = {
            success: false,
            message: message
          };
          response.status(status).json(responseBody);
        } else {
          // Follow RFC 7807 Problem Details format for other endpoints
          const problemDetails = {
            type: `https://api.example.com/problems/${this.getErrorTypeFromStatus(status)}`,
            title: this.getTitleFromStatus(status),
            status,
            detail: message,
            instance: request?.url || '/',
            traceId: requestId
          };
          response.status(status).json(problemDetails);
        }
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
    } catch (sendError) {
      this.logger.error({
        message: 'Failed to send exception response',
        details: {
          error: sendError instanceof Error ? sendError.message : String(sendError),
          status,
          message
        }
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
