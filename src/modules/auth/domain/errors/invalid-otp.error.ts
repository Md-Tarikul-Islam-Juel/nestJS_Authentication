import {DomainError} from '../../../../common/errors/domain-error';
import {ERROR_CODES} from '../../../../common/errors/error-codes';

export class InvalidOtpError extends DomainError {
  constructor() {
    super('Invalid or expired OTP', ERROR_CODES.INVALID_OTP, 401);
  }
}
