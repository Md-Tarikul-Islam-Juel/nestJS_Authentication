import {
  ArgumentsHost,
  Catch,
  ExceptionFilter,
  HttpException,
  HttpStatus,
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
  UnauthorizedException,
  Injectable,
} from '@nestjs/common';
import { Prisma } from '@prisma/client';
import { PrismaClientInitializationError } from '@prisma/client/runtime/library';
import { GqlArgumentsHost } from '@nestjs/graphql';
import { LoggerService } from '../logger/logger.service';

@Catch()
@Injectable()
export class AllExceptionsFilter implements ExceptionFilter {
  constructor(private readonly logger: LoggerService) {}

  catch(exception: unknown, host: ArgumentsHost) {
    const gqlHost = GqlArgumentsHost.create(host);
    const context = gqlHost.getContext();
    const response = context?.res || host.switchToHttp().getResponse();
    const request = context?.req || host.switchToHttp().getRequest();

    const isHttp = host.getType() === 'http';

    const status = exception instanceof HttpException ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;
    let message: string | object = exception instanceof HttpException ? exception.getResponse() : 'Internal Server Error';

    if (typeof message === 'object') {
      message = this.extractMessage(message);
    }

    this.logger.error(
      {
        message: `Status: ${status}, Message: ${message}`,
        details: {
          path: request.url,
          method: request.method,
          body: request.body,
        },
      },
      (exception as any).stack
    );

    if (exception instanceof Prisma.PrismaClientKnownRequestError) {
      if (exception.code === 'P2002') {
        this.handleException(isHttp, response, HttpStatus.CONFLICT, `${exception.meta.target[0]} already exists`);
      } else if (exception.code === 'P2025') {
        this.handleException(isHttp, response, HttpStatus.NOT_FOUND, 'Resource doesn\'t exist or you don\'t have permission');
      } else if (exception.code === 'P2003') {
        this.handleException(isHttp, response, HttpStatus.BAD_REQUEST, 'Error on deleting the resource');
      } else {
        this.handleException(isHttp, response, HttpStatus.INTERNAL_SERVER_ERROR, 'Prisma Client Known Request Error');
      }
    } else if (exception instanceof Prisma.PrismaClientValidationError) {
      this.handleException(isHttp, response, HttpStatus.BAD_REQUEST, 'Validation Error');
    } else if (exception instanceof PrismaClientInitializationError) {
      this.handleException(isHttp, response, HttpStatus.SERVICE_UNAVAILABLE, 'Database connection error');
    } else if (exception instanceof HttpException) {
      if (exception instanceof NotFoundException) {
        this.handleException(isHttp, response, HttpStatus.NOT_FOUND, exception.message);
      } else if (exception instanceof BadRequestException) {
        this.handleException(isHttp, response, HttpStatus.BAD_REQUEST, exception.message);
      } else if (exception instanceof UnauthorizedException) {
        this.handleException(isHttp, response, HttpStatus.UNAUTHORIZED, exception.message);
      } else if (exception instanceof ForbiddenException) {
        this.handleException(isHttp, response, HttpStatus.FORBIDDEN, exception.message);
      } else if (exception instanceof ConflictException) {
        this.handleException(isHttp, response, HttpStatus.CONFLICT, exception.message);
      } else {
        this.handleException(isHttp, response, HttpStatus.INTERNAL_SERVER_ERROR, message);
      }
    } else {
      this.handleException(isHttp, response, HttpStatus.INTERNAL_SERVER_ERROR, 'Internal server error');
    }
  }

  private handleException(isHttp: boolean, response: any, status: number, message: string) {
    if (isHttp) {
      response.status(status).json({
        success: false,
        statusCode: status,
        message,
      });
    } else {
      response.status(status).json({
        errors: [
          {
            message,
            statusCode: status,
          },
        ],
      });
    }
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
