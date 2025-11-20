import { registerAs } from '@nestjs/config';

export default registerAs('queue', () => ({
  email: {
    concurrency: parseInt(process.env.EMAIL_QUEUE_CONCURRENCY ?? '5', 10),
    maxAttempts: parseInt(process.env.EMAIL_QUEUE_MAX_ATTEMPTS ?? '3', 10),
    backoffDelay: parseInt(process.env.EMAIL_QUEUE_BACKOFF_DELAY ?? '5000', 10)
  }
}));
