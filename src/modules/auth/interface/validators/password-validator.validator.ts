import {ValidationArguments, ValidatorConstraint, ValidatorConstraintInterface} from 'class-validator';

@ValidatorConstraint({name: 'isNotBlockedPassword', async: false})
export class IsNotBlockedPassword implements ValidatorConstraintInterface {
  private blockedPasswords = ['123456', 'password', '123456789', 'qwerty', '12345', '12345678', 'abc123', 'password1'];

  validate(password: string, args: ValidationArguments) {
    return !this.blockedPasswords.includes(password);
  }

  defaultMessage(args: ValidationArguments) {
    return 'The password provided is too common and not allowed.';
  }
}
