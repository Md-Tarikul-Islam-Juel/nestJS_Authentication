import {Injectable} from '@nestjs/common';
import {PlatformJwtService} from '../../../../platform/jwt/jwt.service';
import {JwtServicePort, TokenConfig, TokenPayload, Tokens} from '../../domain/repositories/jwt-service.port';

/**
 * JWT Service Adapter
 * Infrastructure adapter implementing JwtServicePort
 * Uses PlatformJwtService for token generation
 */
@Injectable()
export class JwtServiceAdapter implements JwtServicePort {
  constructor(private readonly platformJwtService: PlatformJwtService) {}

  async generateTokens(user: TokenPayload, config: TokenConfig): Promise<Tokens> {
    return this.platformJwtService.generateTokens(user, config);
  }
}
