import { registerAs } from '@nestjs/config';

export default registerAs('queue', () => ({
  email: {
    concurrency: parseInt(process.env.EMAIL_QUEUE_CONCURRENCY, 10) || 5,
    maxAttempts: parseInt(process.env.EMAIL_QUEUE_MAX_ATTEMPTS, 10) || 3,
    backoffDelay: parseInt(process.env.EMAIL_QUEUE_BACKOFF_DELAY, 10) || 5000
  }
}));
