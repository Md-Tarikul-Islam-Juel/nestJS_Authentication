import { JwtService } from '@nestjs/jwt';

export function generateJwtToken(jwtService: JwtService, existingUser): string {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { password, updatedAT, ...restUser } = existingUser;
  const payload = { ...restUser };
  const token = jwtService.sign(payload);
  return token;
}
