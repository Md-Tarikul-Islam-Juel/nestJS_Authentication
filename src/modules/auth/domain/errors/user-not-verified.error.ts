import {DomainError} from '../../../../common/errors/domain-error';
import {ERROR_CODES} from '../../../../common/errors/error-codes';

export class UserNotVerifiedError extends DomainError {
  constructor(email?: string) {
    super(email ? `User with email ${email} is not verified` : 'User is not verified', ERROR_CODES.USER_NOT_VERIFIED, 403);
  }
}
