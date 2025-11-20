import { InjectQueue } from '@nestjs/bullmq';
import { Injectable } from '@nestjs/common';
import { Queue } from 'bullmq';
import { LoggerService } from '../../../common/observability/logger.service';
import { EMAIL_QUEUE_NAME, EmailJobData, EmailJobType, OtpEmailJobData } from '../types/email-queue.types';

/**
 * Email Queue Service
 * Handles adding email jobs to the queue
 */
@Injectable()
export class EmailQueueService {
  constructor(
    @InjectQueue(EMAIL_QUEUE_NAME) private emailQueue: Queue<EmailJobData>,
    private logger: LoggerService
  ) {}

  /**
   * Add OTP email job to the queue
   * @param email - Recipient email address
   * @param otp - One-time password code
   * @param expireTime - OTP expiration time in minutes
   */
  async addOtpEmailJob(email: string, otp: string, expireTime: number): Promise<void> {
    try {
      const jobData: OtpEmailJobData = {
        type: EmailJobType.OTP_EMAIL,
        email,
        otp,
        expireTime
      };

      const job = await this.emailQueue.add(EmailJobType.OTP_EMAIL, jobData, {
        priority: 1, // High priority for OTP emails
        removeOnComplete: true,
        removeOnFail: false // Keep failed jobs for debugging
      });

      this.logger.info({
        message: 'OTP email job added to queue',
        details: {jobId: job.id, email}
      });
    } catch (error) {
      this.logger.error({
        message: 'Failed to add OTP email job to queue',
        details: {email, error: error instanceof Error ? error.message : String(error)}
      });
      throw error;
    }
  }

  /**
   * Get queue health status
   */
  async getQueueHealth(): Promise<{
    waiting: number;
    active: number;
    completed: number;
    failed: number;
  }> {
    const [waiting, active, completed, failed] = await Promise.all([
      this.emailQueue.getWaitingCount(),
      this.emailQueue.getActiveCount(),
      this.emailQueue.getCompletedCount(),
      this.emailQueue.getFailedCount()
    ]);

    return {waiting, active, completed, failed};
  }
}
