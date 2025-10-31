import {Injectable} from '@nestjs/common';
import {ConfigService} from '@nestjs/config';
import {PrismaClient} from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient {
  constructor(config: ConfigService) {
    // Get DATABASE_URL or construct it from individual components
    const databaseUrl = PrismaService.getDatabaseUrl(config);

    super({
      datasources: {
        db: {
          url: databaseUrl
        }
      }
    });
  }

  /**
   * Get database URL from DATABASE_URL env var, or construct it from individual components
   */
  private static getDatabaseUrl(config: ConfigService): string {
    // If DATABASE_URL is provided and doesn't contain variable placeholders, use it directly
    const databaseUrl = config.get<string>('DATABASE_URL');

    if (databaseUrl && !databaseUrl.includes('${')) {
      // Valid DATABASE_URL without variable substitution
      return databaseUrl;
    }

    // Construct DATABASE_URL from individual components
    const host = config.get<string>('DATABASE_HOST') || 'localhost';
    const port = config.get<number>('DATABASE_PORT') || 5432;
    const user = config.get<string>('DATABASE_USER') || 'postgres';
    const password = config.get<string>('DATABASE_PASSWORD') || '';
    const database = config.get<string>('DATABASE_NAME') || 'postgres';
    const schema = config.get<string>('DATABASE_SCHEMA') || 'public';

    // URL-encode password to handle special characters
    const encodedPassword = encodeURIComponent(password);

    return `postgresql://${user}:${encodedPassword}@${host}:${port}/${database}?schema=${schema}`;
  }
}
