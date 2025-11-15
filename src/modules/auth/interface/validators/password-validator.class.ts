import {Inject, Injectable} from '@nestjs/common';
import {ValidationArguments, ValidatorConstraint, ValidatorConstraintInterface} from 'class-validator';
import {PasswordValidationService} from '../../application/services/password-validation.service';

/**
 * Password Validator (Framework Adapter)
 * Thin adapter that delegates to PasswordValidationService in application layer
 * Following Clean Architecture: interface layer adapts framework decorators to application services
 */
@ValidatorConstraint({name: 'passwordValidation', async: false})
@Injectable()
export class PasswordValidator implements ValidatorConstraintInterface {
  constructor(
    @Inject(PasswordValidationService)
    private readonly passwordValidationService: PasswordValidationService
  ) {}

  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  validate(password: string, _args: ValidationArguments): boolean {
    const result = this.passwordValidationService.validatePassword(password);
    return result.isValid;
  }

  defaultMessage(args: ValidationArguments): string {
    const password = (args?.value as string) || '';
    if (!password) {
      return 'Password is required';
    }
    const result = this.passwordValidationService.validatePassword(password);
    return result.error || 'Password validation failed';
  }
}
