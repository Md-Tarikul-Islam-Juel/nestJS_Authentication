import {DomainError} from '../../../../common/errors/domain-error';
import {ERROR_CODES} from '../../../../common/errors/error-codes';

export class InvalidCredentialsError extends DomainError {
  constructor() {
    super('Invalid credentials', ERROR_CODES.INVALID_CREDENTIALS, 401);
  }
}
