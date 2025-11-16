export class RefreshTokenCommand {
  constructor(
    public readonly userId: number,
    public readonly email: string,
    public readonly sid?: string,
    public readonly jti?: string
  ) {}

  static fromRequest(user: {id: number; email: string; sid?: string; jti?: string}): RefreshTokenCommand {
    return new RefreshTokenCommand(user.id, user.email, user.sid, user.jti);
  }
}
