import {CallHandler, ExecutionContext, Injectable, NestInterceptor} from '@nestjs/common';
import {Observable} from 'rxjs';
import {getVersionMetadata, isVersionDeprecated} from '../version.constants';

/**
 * Version Deprecation Interceptor
 * Adds deprecation headers when using deprecated API versions
 * Following REST best practices: warn clients about deprecated versions
 */
@Injectable()
export class VersionDeprecationInterceptor implements NestInterceptor {
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();

    // Extract version from request (works for URI, Header, or Media-Type versioning)
    const version = this.extractVersion(request);

    if (version && isVersionDeprecated(version)) {
      const metadata = getVersionMetadata(version);
      if (metadata) {
        // Add deprecation warning header
        response.setHeader('Deprecation', 'true');
        response.setHeader('Sunset', metadata.sunsetAt || '');
        if (metadata.migrationGuide) {
          response.setHeader('Link', `<${metadata.migrationGuide}>; rel="deprecation"`);
        }
        // Add custom header with deprecation info
        response.setHeader('X-API-Version-Status', metadata.status);
        if (metadata.deprecatedAt) {
          response.setHeader('X-API-Version-Deprecated-At', metadata.deprecatedAt);
        }
      }
    }

    return next.handle();
  }

  /**
   * Extract API version from request
   * Supports URI, Header, and Media-Type versioning
   */
  private extractVersion(request: any): string | null {
    // URI versioning: /v1/auth/signup
    const uriMatch = request.url?.match(/\/v(\d+)\//);
    if (uriMatch) {
      return uriMatch[1];
    }

    // Header versioning: X-API-Version: 1
    const headerVersion = request.headers?.['x-api-version'];
    if (headerVersion) {
      return String(headerVersion);
    }

    // Media-Type versioning: application/json;v=1
    const acceptHeader = request.headers?.accept;
    if (acceptHeader) {
      const mediaTypeMatch = acceptHeader.match(/v=(\d+)/);
      if (mediaTypeMatch) {
        return mediaTypeMatch[1];
      }
    }

    return null;
  }
}
