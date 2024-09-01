import { Injectable } from '@nestjs/common';

@Injectable()
export class CommonAuthService {
  removeSensitiveData(obj: any, sensitiveFields: string[]): any {
    const filteredObj = { ...obj };

    sensitiveFields.forEach(field => {
      delete filteredObj[field];
    });

    return filteredObj;
  }
}
