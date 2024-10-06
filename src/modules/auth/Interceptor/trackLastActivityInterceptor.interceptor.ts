import {Injectable, NestInterceptor, ExecutionContext, CallHandler} from '@nestjs/common';
import {Observable} from 'rxjs';
import {LastActivityTrackService} from '../services/lastActivityTrack.service';

@Injectable()
export class TrackLastActivityInterceptor implements NestInterceptor {
  constructor(private readonly lastActivityService: LastActivityTrackService) {}

  async intercept(context: ExecutionContext, next: CallHandler): Promise<Observable<any>> {
    const request = context.switchToHttp().getRequest();

    if (request.user) {
      const userId = request.user.id;
      await this.lastActivityService.updateLastActivityToRedis(userId);
    }

    return next.handle();
  }
}
