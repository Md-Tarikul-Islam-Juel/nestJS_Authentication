import {DomainError} from '../../../../common/errors/domain-error';
import {ERROR_CODES} from '../../../../common/errors/error-codes';

export class EmailServiceError extends DomainError {
  constructor(message: string = 'Failed to send email') {
    super(message, ERROR_CODES.EMAIL_SERVICE_ERROR, 500);
  }
}
