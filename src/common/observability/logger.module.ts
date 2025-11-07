import {Global, Module} from '@nestjs/common';
import {ConfigModule} from '@nestjs/config';
import {PiiMaskerService} from '../data-protection/pii-masker.service';
import {LoggerService} from './logger.service';

@Global()
@Module({
  imports: [ConfigModule],
  providers: [LoggerService, PiiMaskerService],
  exports: [LoggerService, PiiMaskerService]
})
export class LoggerModule {}
