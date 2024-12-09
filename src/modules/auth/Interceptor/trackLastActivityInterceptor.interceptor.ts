import {Injectable, NestInterceptor, ExecutionContext, CallHandler} from '@nestjs/common';
import {Observable} from 'rxjs';
import {GqlExecutionContext} from '@nestjs/graphql';
import {LastActivityTrackService} from '../services/lastActivityTrack.service';

@Injectable()
export class TrackLastActivityInterceptor implements NestInterceptor {
  constructor(private readonly lastActivityService: LastActivityTrackService) {}

  async intercept(context: ExecutionContext, next: CallHandler): Promise<Observable<any>> {
    const contextType = context.getType<'http' | 'graphql'>();

    let userId: number | null = null;

    if (contextType === 'http') {
      // Handling HTTP requests
      const request = context.switchToHttp().getRequest();
      if (request.user) {
        userId = request.user.id;
      }
    } else if (contextType === 'graphql') {
      // Handling GraphQL requests
      const gqlContext = GqlExecutionContext.create(context);
      const request = gqlContext.getContext().req;
      if (request.user) {
        userId = request.user.id;
      }
    }

    // If user ID exists, update the last activity
    if (userId) {
      await this.lastActivityService.updateLastActivityToRedis(userId);
    }

    return next.handle();
  }
}
