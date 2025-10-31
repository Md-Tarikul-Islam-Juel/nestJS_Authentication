import {DomainError} from '../../../../common/errors/domain-error';
import {ERROR_CODES} from '../../../../common/errors/error-codes';

export class UserNotFoundError extends DomainError {
  constructor(email?: string) {
    super(email ? `User with email ${email} not found` : 'User not found', ERROR_CODES.USER_NOT_FOUND, 404);
  }
}
