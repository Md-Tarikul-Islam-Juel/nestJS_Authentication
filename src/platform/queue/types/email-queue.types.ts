/**
 * Email Queue Types
 * Type definitions for email queue jobs and data
 */

/**
 * Email job types enum
 */
export enum EmailJobType {
  OTP_EMAIL = 'otp-email',
  // Future email types can be added here
  // WELCOME_EMAIL = 'welcome-email',
  // PASSWORD_RESET = 'password-reset',
}

/**
 * Base email job data interface
 */
export interface BaseEmailJobData {
  type: EmailJobType;
  email: string;
}

/**
 * OTP email job data
 */
export interface OtpEmailJobData extends BaseEmailJobData {
  type: EmailJobType.OTP_EMAIL;
  otp: string;
  expireTime: number;
}

/**
 * Union type for all email job data types
 */
export type EmailJobData = OtpEmailJobData;

/**
 * Queue names
 */
export const EMAIL_QUEUE_NAME = 'email-queue';
