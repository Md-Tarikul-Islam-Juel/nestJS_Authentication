export class RefreshTokenCommand {
  constructor(
    public readonly userId: number,
    public readonly email: string
  ) {}

  static fromRequest(user: {id: number; email: string}): RefreshTokenCommand {
    return new RefreshTokenCommand(user.id, user.email);
  }
}
