import * as otpGenerator from 'otp-generator';

export class OtpDomainService {
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

  validateOtpLength(otp: string, expectedLength: number): boolean {
    return otp.length === expectedLength && /^\d+$/.test(otp);
  }
}
