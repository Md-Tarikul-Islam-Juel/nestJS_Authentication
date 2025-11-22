import { registerDecorator, ValidationArguments, ValidationOptions } from 'class-validator';
import { SSRFProtectionService } from '../security/ssrf-protection.service';

/**
 * Decorator to validate that a URL is secure and not vulnerable to SSRF
 * Uses SSRFProtectionService to check for private IPs and blocked hosts
 */
export function IsSecureUrl(validationOptions?: ValidationOptions) {
    return function (object: Object, propertyName: string) {
        registerDecorator({
            name: 'isSecureUrl',
            target: object.constructor,
            propertyName: propertyName,
            options: validationOptions,
            validator: {
                validate(value: any, args: ValidationArguments) {
                    if (!value) return true; // Allow empty values (use @IsNotEmpty if required)
                    const ssrfProtection = new SSRFProtectionService();
                    return typeof value === 'string' && ssrfProtection.isUrlSafe(value);
                },
                defaultMessage(args: ValidationArguments) {
                    return 'URL is not allowed (potential SSRF vulnerability)';
                },
            },
        });
    };
}
