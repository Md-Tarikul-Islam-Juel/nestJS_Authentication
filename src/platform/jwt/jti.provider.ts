import {Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {randomBytes} from 'crypto';
import {randomUUID} from 'crypto';

type JtiStrategy = 'uuid' | 'nanoid' | 'random-bytes';

@Injectable()
export class JtiProvider {
  constructor(private readonly configService: ConfigService) {}

  generateJti(): string {
    const strategy = (this.configService.get<string>('authConfig.token.jti.strategy') || 'uuid') as JtiStrategy;
    const prefix = this.configService.get<string>('authConfig.token.jti.prefix') || '';
    const length = this.coerceInt(this.configService.get<string>('authConfig.token.jti.length'), 21);

    let core: string;
    switch (strategy) {
      case 'uuid':
        core = randomUUID();
        break;
      case 'random-bytes': {
        const size = Math.max(16, Math.min(128, length));
        core = randomBytes(size).toString('base64url').slice(0, length);
        break;
      }
      case 'nanoid':
      default: {
        // Simple nanoid-like by base64url of random bytes, clipped
        const size = Math.max(16, Math.ceil(length * 0.75));
        core = randomBytes(size).toString('base64url').slice(0, length);
        break;
      }
    }
    return `${prefix}${core}`;
  }

  generateSessionId(): string {
    // Session id is simpler and stable per device; default to uuid
    const prefix = this.configService.get<string>('authConfig.token.session.prefix') || 'sid_';
    return `${prefix}${randomUUID()}`;
  }

  private coerceInt(value: string | number | undefined, fallback: number): number {
    if (typeof value === 'number') return value;
    if (!value) return fallback;
    const parsed = parseInt(value as string, 10);
    return Number.isFinite(parsed) ? parsed : fallback;
  }
}


