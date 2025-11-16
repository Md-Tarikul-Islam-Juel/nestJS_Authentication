import {Module} from '@nestjs/common';
import {JwtModule} from '@nestjs/jwt';
import {PassportModule} from '@nestjs/passport';
import {PlatformJwtService} from './jwt.service';
import {JtiProvider} from './jti.provider';

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
  providers: [PlatformJwtService, JtiProvider],
  exports: [JwtModule, PassportModule, PlatformJwtService, JtiProvider]
})
export class PlatformJwtModule {}

