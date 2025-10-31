import {DomainError} from '../../../../common/errors/domain-error';
import {ERROR_CODES} from '../../../../common/errors/error-codes';

export class AccountLockedError extends DomainError {
  constructor(remainingMinutes?: number) {
    const message = remainingMinutes ? `Your account is locked. Please try again in ${remainingMinutes} minutes.` : 'Your account is locked.';
    super(message, ERROR_CODES.ACCOUNT_LOCKED, 401);
  }
}
