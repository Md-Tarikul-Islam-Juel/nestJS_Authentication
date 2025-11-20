import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PassportStrategy } from '@nestjs/passport';
import { Profile, Strategy } from 'passport-facebook';

interface FacebookUser {
  email: string;
  authorizerId: string;
  firstName: string;
  lastName: string;
  loginSource: string;
}

@Injectable()
export class FacebookStrategy extends PassportStrategy(Strategy, 'facebook') {
  constructor(private readonly configService: ConfigService) {
    super({
      clientID: configService.get('FACEBOOK_CLIENT_ID'),
      clientSecret: configService.get('FACEBOOK_CLIENT_SECRET'),
      callbackURL: configService.get('FACEBOOK_CALLBACK_URL'),
      profileFields: ['email', 'name']
    });
  }

  async validate(
    accessToken: string,
    refreshToken: string,
    profile: Profile,
    done: (error: any, user?: FacebookUser | boolean | null) => void
  ): Promise<void> {
    try {
      const user: FacebookUser = {
        authorizerId: profile.id,
        firstName: profile.name?.givenName ?? '',
        lastName: profile.name?.familyName ?? '',
        email: `${profile.id}@facebook.com`,
        loginSource: 'facebook'
      };
      done(null, user);
    } catch (error) {
      done(error, false);
    }
  }
}
