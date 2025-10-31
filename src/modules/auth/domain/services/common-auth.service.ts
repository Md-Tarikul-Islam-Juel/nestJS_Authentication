import {Injectable} from '@nestjs/common';
import * as otpGenerator from 'otp-generator';

@Injectable()
export class CommonAuthService {
  removeSensitiveData(obj: any, sensitiveFields: string[]): any {
    const filteredObj = {...obj};

    sensitiveFields.forEach(field => {
      delete filteredObj[field];
    });

    return filteredObj;
  }

  generateOtp(length: number): string {
    return otpGenerator.generate(length, {
      digits: true,
      upperCase: false,
      lowercase: false,
      upperCaseAlphabets: false,
      lowerCaseAlphabets: false,
      specialChars: false
    });
  }
}
