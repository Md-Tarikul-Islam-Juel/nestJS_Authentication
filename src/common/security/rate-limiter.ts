import {rateLimit} from 'express-rate-limit';

export const rateLimiterConfig = rateLimit({
  windowMs: 1000 * 60,
  limit: 50,
  message: 'Too many requests, please try again later.',
  standardHeaders: true,
  legacyHeaders: false
});
