import { BullModule } from '@nestjs/bullmq';
import { ConfigService } from '@nestjs/config';
import { EMAIL_QUEUE_NAME } from '../types/email-queue.types';

/**
 * Email Queue Configuration Factory
 * Configures BullMQ with Redis connection and queue options
 */
export const emailQueueConfig = BullModule.forRootAsync({
  useFactory: (configService: ConfigService) => ({
    connection: {
      host: configService.get<string>('redis.host'),
      port: configService.get<number>('redis.port')
    },
    defaultJobOptions: {
      attempts: configService.get<number>('queue.email.maxAttempts', 3),
      backoff: {
        type: 'exponential',
        delay: configService.get<number>('queue.email.backoffDelay', 5000)
      },
      removeOnComplete: {
        age: 3600, // Keep completed jobs for 1 hour
        count: 100 // Keep last 100 completed jobs
      },
      removeOnFail: {
        age: 86400 // Keep failed jobs for 24 hours
      }
    }
  }),
  inject: [ConfigService]
});

/**
 * Email Queue Registration
 * Registers the email queue with specific options
 */
export const emailQueueRegistration = BullModule.registerQueue({
  name: EMAIL_QUEUE_NAME
});
