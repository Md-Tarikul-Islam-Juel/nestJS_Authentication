export const AUTH_ROUTES = {
  BASE: 'auth',
  SIGNUP: 'signup',
  SIGNIN: 'signin',
  RESEND_OTP: 'resend',
  VERIFY_OTP: 'verify',
  FORGET_PASSWORD: 'forget-password',
  CHANGE_PASSWORD: 'change-password',
  REFRESH_TOKEN: 'refresh-token',
  LOGOUT_ALL: 'logout-all',
  GOOGLE: 'google',
  GOOGLE_CALLBACK: 'google/callback',
  FACEBOOK: 'facebook',
  FACEBOOK_CALLBACK: 'facebook/callback'
} as const;

export const AUTH_MESSAGES = {
  EMAIL_SUBJECT: 'Your OTP',
  VERIFY_YOUR_USER: 'Verify your user',
  OTP_EMAIL_SENT: 'OTP email sent',
  SIGNUP_SUCCESSFUL: 'Signup successful',
  SIGNIN_SUCCESSFUL: 'Signin successful',
  USER_ALREADY_EXISTS: 'User already exists',
  UNAUTHORIZED: 'Unauthorized',
  OTP_VERIFICATION_FAILED: 'OTP verification failed',
  OTP_AUTHORIZED: 'OTP authorized',
  OTP_EMAIL_SEND_FAIL: 'OTP email send fail',
  FAILED_TO_CHANGE_PASSWORD: 'Failed to change password',
  PASSWORD_UPDATED: 'Your password has been updated',
  OLD_PASSWORD_REQUIRED: 'Old password is required',
  NEW_PASSWORD_SAME_AS_OLD: 'New password must be different from the old password',
  INVALID_REFRESH_TOKEN: 'Invalid Refresh Token',
  USER_NOT_FOUND: 'User Not Found',
  FAILED_TO_SEND_OTP_EMAIL: 'Failed to send OTP email',
  INVALID_OR_EXPIRED_OTP: 'Invalid or expired OTP',
  TOKENS_GENERATED: 'Successfully generate new tokens'
} as const;
