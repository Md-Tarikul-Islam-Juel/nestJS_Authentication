import {CallHandler, ExecutionContext, Injectable, NestInterceptor} from '@nestjs/common';
import {GqlExecutionContext} from '@nestjs/graphql';
import {Observable} from 'rxjs';
import {LastActivityTrackService} from '../../../infrastructure/services/last-activity-track.service';

@Injectable()
export class TrackLastActivityInterceptor implements NestInterceptor {
  constructor(private readonly lastActivityService: LastActivityTrackService) {}

  async intercept(context: ExecutionContext, next: CallHandler): Promise<Observable<any>> {
    const contextType = context.getType<'http' | 'graphql'>();

    let userId: number | null = null;

    if (contextType === 'http') {
      const request = context.switchToHttp().getRequest();
      if (request.user) {
        userId = request.user.id;
      }
    } else if (contextType === 'graphql') {
      const gqlContext = GqlExecutionContext.create(context);
      const request = gqlContext.getContext().req;
      if (request.user) {
        userId = request.user.id;
      }
    }

    // Don't block on activity tracking - fire and forget
    if (userId) {
      this.lastActivityService.updateLastActivityToRedis(userId).catch(error => {
        // Silently fail - activity tracking shouldn't block requests
        console.error('Failed to update last activity:', error);
      });
    }

    return next.handle();
  }
}
