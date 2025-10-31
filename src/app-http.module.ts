import {Module} from '@nestjs/common';
import {APP_FILTER} from '@nestjs/core';
import {ProblemDetailsFilter} from './common/http/filters/problem-details.filter';
import {AuthModule} from './modules/auth/auth.module';

@Module({
  imports: [AuthModule],
  providers: [
    {
      provide: APP_FILTER,
      useClass: ProblemDetailsFilter
    }
  ]
})
export class AppHttpModule {}
