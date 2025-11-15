import {IsNotEmpty, IsString, Validate} from 'class-validator';
import {PasswordValidator} from './password-validator.class';

/**
 * Password Validation Decorator
 * Applies comprehensive password validation using PasswordValidator
 * Following Clean Architecture: uses validator class with DI support
 */
export function PasswordValidation(): PropertyDecorator {
  return function (target: object, propertyKey: string | symbol) {
    IsString()(target, propertyKey);
    IsNotEmpty({message: 'Password is required'})(target, propertyKey);
    Validate(PasswordValidator)(target, propertyKey);
  };
}
