import {CallHandler, ExecutionContext, Injectable, NestInterceptor} from '@nestjs/common';
import {Request, Response} from 'express';
import {Observable, throwError} from 'rxjs';
import {catchError, tap} from 'rxjs/operators';
import {PiiMaskerService} from '../../data-protection/pii-masker.service';
import {LoggerService} from '../../observability/logger.service';

@Injectable()
export class LoggingInterceptor implements NestInterceptor {
  constructor(
    private readonly logger: LoggerService,
    private readonly piiMasker: PiiMaskerService
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    if (context.getType() !== 'http') {
      return next.handle();
    }

    const request = context.switchToHttp().getRequest<Request>();
    const response = context.switchToHttp().getResponse<Response>();
    const {method, originalUrl, body, query, headers} = request;
    const requestId = (headers['x-request-id'] as string) || undefined;
    const sanitizedRequestBody = this.sanitizePayload(body);
    const sanitizedQuery = this.sanitizePayload(query);
    const start = Date.now();

    return next.handle().pipe(
      tap(data => {
        const duration = Date.now() - start;
        const sanitizedResponse = this.sanitizePayload(data);
        this.logger.info(
          {
            message: 'HTTP request completed',
            details: {
              method,
              url: originalUrl,
              statusCode: response.statusCode,
              durationMs: duration,
              requestId,
              request: {body: sanitizedRequestBody, query: sanitizedQuery},
              response: sanitizedResponse
            }
          },
          'LoggingInterceptor'
        );
      }),
      catchError(error => {
        const duration = Date.now() - start;
        this.logger.error(
          {
            message: 'HTTP request failed',
            details: {
              method,
              url: originalUrl,
              statusCode: response.statusCode,
              durationMs: duration,
              requestId,
              request: {body: sanitizedRequestBody, query: sanitizedQuery},
              error: error instanceof Error ? this.piiMasker.maskString(error.message) : String(error)
            }
          },
          'LoggingInterceptor'
        );
        return throwError(() => error);
      })
    );
  }

  private sanitizePayload(payload: unknown): unknown {
    if (payload === null || payload === undefined) {
      return payload;
    }

    if (typeof payload === 'object' || Array.isArray(payload)) {
      return this.piiMasker.maskDeep(payload);
    }

    if (typeof payload === 'string') {
      return this.piiMasker.maskString(payload);
    }

    return payload;
  }
}


