import {Global, Module} from '@nestjs/common';
import {ConfigModule as NestConfigModule} from '@nestjs/config';
import tokenConfig from '../modules/token/config/token.config';
import authConfig from './auth.config';
import {envSchema} from './env.schema';

@Global()
@Module({
  imports: [
    NestConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
      load: [authConfig, tokenConfig],
      validationSchema: envSchema,
      validationOptions: {
        allowUnknown: true, // Allow other env vars not in schema
        abortEarly: false // Show all validation errors, not just the first one
      }
    })
  ],
  exports: [NestConfigModule]
})
export class ConfigModule {}
