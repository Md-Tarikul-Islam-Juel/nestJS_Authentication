import { Global, Module } from '@nestjs/common';
import { ConfigModule as NestConfigModule } from '@nestjs/config';
import { existsSync } from 'fs';
import authConfig from './auth.config';
import { validateEnv } from './env.schema';
import queueConfig from './queue.config';

const DEFAULT_ENV = 'development';
const nodeEnv = process.env.NODE_ENV?.trim() || DEFAULT_ENV;
const candidateEnvs = [`.env.${nodeEnv}.local`, `.env.${nodeEnv}`, '.env.local', '.env'];
const envFilePath = candidateEnvs.filter(path => existsSync(path));

@Global()
@Module({
  imports: [
    NestConfigModule.forRoot({
      isGlobal: true,
      envFilePath: envFilePath.length > 0 ? envFilePath : undefined,
      ignoreEnvFile: envFilePath.length === 0,
      load: [authConfig, queueConfig],
      validate: validateEnv
    })
  ],
  exports: [NestConfigModule]
})
export class ConfigModule {}
