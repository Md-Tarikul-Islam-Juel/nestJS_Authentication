import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

@Injectable()
export class PasswordService {
  constructor() {
  }

  async hashPassword(password: string, saltRounds: number): Promise<string> {
    return bcrypt.hash(password, saltRounds);
  }

  public randomPasswordGenerator(length: number): string {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';
    let code: string = '';

    const randomNumber: number = Math.floor(Math.random() * 10);
    code += randomNumber.toString();

    for (let i: number = 1; i < length; i++) {
      const randomIndex: number = Math.floor(Math.random() * charset.length);
      code += charset[randomIndex];
    }

    return code;
  }
}
