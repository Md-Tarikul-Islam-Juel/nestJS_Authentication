import {
  MinLength,
  MaxLength,
  Matches,
  IsNotEmpty,
  IsString, Validate,
} from 'class-validator';
import { IsNotBlockedPassword } from '../validators/password-validator.validator';
import * as dotenv from 'dotenv';

dotenv.config();

function isTrue(value: string | undefined): boolean {
  return value?.toLowerCase() === 'true';
}

export function PasswordValidation(): PropertyDecorator {
  return function(target: Object, propertyKey: string | symbol) {
    IsString()(target, propertyKey);
    IsNotEmpty({ message: 'Password is required' })(target, propertyKey);
    MinLength(Number(process.env.PASSWORD_MIN_LENGTH), {
      message: `Password must be at least ${process.env.PASSWORD_MIN_LENGTH} characters long`,
    })(target, propertyKey);
    MaxLength(Number(process.env.PASSWORD_MAX_LENGTH), {
      message: `Password must be at most ${process.env.PASSWORD_MAX_LENGTH} characters long`,
    })(target, propertyKey);

    if (isTrue(process.env.PASSWORD_REQUIRE_LOWERCASE)) {
      Matches(/(?=.*[a-z])/, {
        message: 'Password must contain at least one lowercase letter',
      })(target, propertyKey);
    }

    if (isTrue(process.env.PASSWORD_REQUIRE_UPPERCASE)) {
      Matches(/(?=.*[A-Z])/, {
        message: 'Password must contain at least one uppercase letter',
      })(target, propertyKey);
    }

    if (isTrue(process.env.PASSWORD_REQUIRE_NUMBERS)) {
      Matches(/(?=.*\d)/, {
        message: 'Password must contain at least one number',
      })(target, propertyKey);
    }

    if (isTrue(process.env.PASSWORD_REQUIRE_SPECIAL_CHARACTERS)) {
      const specialCharacters = '!@#$%^&*()_+[]{}|;:,.<>?'; // Define the special characters you want to allow
      Matches(new RegExp(`(?=.*[${specialCharacters.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')}])`), {
        message: `Password must contain at least one special character (${specialCharacters})`,
      })(target, propertyKey);
    }

    if (isTrue(process.env.PASSWORD_DISALLOW_REPEATING)) {
      Matches(/^(?!.*(.)\1{1,}).*$/, {
        message: 'Password must not contain consecutive repeating characters',
      })(target, propertyKey);
    }

    if (isTrue(process.env.PASSWORD_DISALLOW_SEQUENTIAL)) {
      Matches(/^(?!.*(?:012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)).*$/, {
        message: 'Password must not contain sequential characters',
      })(target, propertyKey);
    }

    if (isTrue(process.env.PASSWORD_BLACKLIST_COMMON)) {
      Validate(IsNotBlockedPassword)(target, propertyKey);
    }
  };
}
