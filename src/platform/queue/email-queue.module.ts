import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { LoggerModule } from '../../common/observability/logger.module';
import { emailQueueConfig, emailQueueRegistration } from './config/email-queue.config';
import { EmailQueueProcessor } from './processors/email-queue.processor';
import { EmailQueueService } from './services/email-queue.service';

/**
 * Email Queue Module
 * Provides email queue functionality using BullMQ
 */
@Module({
  imports: [
    ConfigModule,
    LoggerModule,
    emailQueueConfig,
    emailQueueRegistration,
    // MailerModule is needed by the processor
    // It will be configured in the auth module
  ],
  providers: [EmailQueueService, EmailQueueProcessor],
  exports: [EmailQueueService]
})
export class EmailQueueModule {}
