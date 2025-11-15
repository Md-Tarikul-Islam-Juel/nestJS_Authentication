import type {OAuthUser} from '../types/auth.types';

export class OAuthSignInCommand {
  constructor(
    public readonly email: string,
    public readonly firstName?: string,
    public readonly lastName?: string,
    public readonly loginSource: string = 'google',
    public readonly mfaEnabled?: boolean,
    public readonly authorizerId?: string
  ) {}

  static fromUser(user: OAuthUser): OAuthSignInCommand {
    return new OAuthSignInCommand(user.email, user.firstName, user.lastName, user.loginSource || 'google', false, user.authorizerId);
  }
}
