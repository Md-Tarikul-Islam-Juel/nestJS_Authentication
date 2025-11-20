import { MailerService } from '@nestjs-modules/mailer';
import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Job } from 'bullmq';
import { LoggerService } from '../../../common/observability/logger.service';
import { EMAIL_QUEUE_NAME, EmailJobData, EmailJobType } from '../types/email-queue.types';

/**
 * Email Queue Processor
 * Processes email jobs from the queue
 */
@Processor(EMAIL_QUEUE_NAME)
@Injectable()
export class EmailQueueProcessor extends WorkerHost {
  private readonly otpSenderMail: string;

  constructor(
    private mailerService: MailerService,
    private configService: ConfigService,
    private logger: LoggerService
  ) {
    super();
    this.otpSenderMail = this.configService.get<string>('authConfig.email.email') ?? '';
  }

  /**
   * Process email jobs
   */
  async process(job: Job<EmailJobData>): Promise<void> {
    this.logger.info({
      message: 'Processing email job',
      details: {jobId: job.id, type: job.data.type, email: job.data.email}
    });

    try {
      switch (job.data.type) {
        case EmailJobType.OTP_EMAIL:
          await this.processOtpEmail(job);
          break;
        default:
          throw new Error(`Unknown email job type: ${job.data.type}`);
      }

      this.logger.info({
        message: 'Email job completed successfully',
        details: {jobId: job.id, type: job.data.type, email: job.data.email}
      });
    } catch (error) {
      this.logger.error({
        message: 'Email job failed',
        details: {
          jobId: job.id,
          type: job.data.type,
          email: job.data.email,
          error: error instanceof Error ? error.message : String(error),
          attemptsMade: job.attemptsMade
        }
      });
      throw error; // Re-throw to trigger retry mechanism
    }
  }

  /**
   * Process OTP email job
   */
  private async processOtpEmail(job: Job<EmailJobData>): Promise<void> {
    if (job.data.type !== EmailJobType.OTP_EMAIL) {
      throw new Error('Invalid job type for OTP email processing');
    }

    const {email, otp, expireTime} = job.data;

    const mailOptions = {
      to: email,
      from: this.otpSenderMail,
      subject: 'Your OTP Code',
      text: `Your OTP code is: ${otp}. It is valid for ${expireTime} minutes.`
    };

    await this.mailerService.sendMail(mailOptions);
  }

  /**
   * Handle job completion
   */
  async onCompleted(job: Job<EmailJobData>) {
    this.logger.info({
      message: 'Email job completed',
      details: {jobId: job.id, email: job.data.email}
    });
  }

  /**
   * Handle job failure
   */
  async onFailed(job: Job<EmailJobData>, error: Error) {
    this.logger.error({
      message: 'Email job failed permanently',
      details: {
        jobId: job.id,
        email: job.data.email,
        error: error.message,
        attemptsMade: job.attemptsMade
      }
    });
  }
}
