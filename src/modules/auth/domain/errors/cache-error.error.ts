import {DomainError} from '../../../../common/errors/domain-error';
import {ERROR_CODES} from '../../../../common/errors/error-codes';

export class CacheError extends DomainError {
  constructor(message: string = 'Cache service unavailable. Please try again.') {
    super(message, ERROR_CODES.CACHE_ERROR, 503);
  }
}
