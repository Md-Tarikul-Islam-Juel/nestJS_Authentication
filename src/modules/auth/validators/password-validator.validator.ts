import {
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
} from 'class-validator';

@ValidatorConstraint({ name: 'isNotBlockedPassword', async: false })
export class IsNotBlockedPassword implements ValidatorConstraintInterface {
  private blockedPasswords = [
    '123456',
    'password',
    '123456789',
    'qwerty',
    '12345',
    '12345678',
    'abc123',
    'password1',
    // Add more blocked passwords as needed
  ];

  validate(password: string, args: ValidationArguments) {
    return !this.blockedPasswords.includes(password);
  }

  defaultMessage(args: ValidationArguments) {
    return 'The password provided is too common and not allowed.';
  }
}

