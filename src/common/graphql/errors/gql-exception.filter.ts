import {ArgumentsHost, Catch, ExceptionFilter, HttpException, HttpStatus} from '@nestjs/common';
import {GqlArgumentsHost} from '@nestjs/graphql';
import {LoggerService} from '../../observability/logger.service';

@Catch()
export class GqlExceptionFilter implements ExceptionFilter {
  constructor(private readonly logger: LoggerService) {}

  catch(exception: unknown, host: ArgumentsHost) {
    // Only handle GraphQL requests - check if this is actually a GraphQL context
    const contextType = host.getType() as string;

    // If it's not a GraphQL context, skip this filter and let HTTP filter handle it
    if (contextType !== 'graphql') {
      // Don't handle the exception - let other filters (HTTP filter) handle it
      // In NestJS, if a filter doesn't set a response, the next filter gets a chance
      return;
    }

    try {
      const gqlHost = GqlArgumentsHost.create(host);
      const context = gqlHost.getContext();

      const status = exception instanceof HttpException ? exception.getStatus() : HttpStatus.INTERNAL_SERVER_ERROR;
      const message = exception instanceof HttpException ? exception.message : 'Internal Server Error';

      this.logger.error({
        message: `GraphQL Error: ${message}`,
        details: {
          status,
          error: exception instanceof Error ? exception.message : String(exception)
        }
      });

      // For GraphQL, exceptions are automatically formatted by Apollo Server
      // Just log and let GraphQL handle the response format
      return exception;
    } catch {
      // If GqlArgumentsHost creation fails, this isn't a GraphQL request
      // Skip handling - let HTTP filter handle it
      return;
    }
  }
}
