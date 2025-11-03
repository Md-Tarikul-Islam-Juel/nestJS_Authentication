import {Module} from '@nestjs/common';
import {JwtModule} from '@nestjs/jwt';
import {PassportModule} from '@nestjs/passport';
import {PlatformJwtService} from './jwt.service';

/**
 * Platform JWT Module
 * Centralizes JWT infrastructure (token generation/validation)
 * This is concrete infrastructure, not bounded context
 */
@Module({
  imports: [
    PassportModule,
    JwtModule.register({}) // JWT options configured via ConfigService at usage time
  ],
  providers: [PlatformJwtService],
  exports: [JwtModule, PassportModule, PlatformJwtService]
})
export class PlatformJwtModule {}

