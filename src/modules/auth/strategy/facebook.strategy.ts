import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile } from 'passport-facebook';
import { ConfigService } from '@nestjs/config';

interface FacebookUser {
  email:string;
  authorizerId: string;
  firstName: string;
  lastName: string;
  loginSource:string;
  // Other user data as needed
}

@Injectable()
export class FacebookStrategy extends PassportStrategy(Strategy, 'facebook') {
  constructor(private readonly configService: ConfigService) {
    super({
      clientID: configService.get('FACEBOOK_CLIENT_ID'),
      clientSecret: configService.get('FACEBOOK_CLIENT_SECRET'),
      callbackURL: configService.get('FACEBOOK_CALLBACK_URL'),
      profileFields: ['email', 'name'],
    });
  }

  async validate(accessToken: string, refreshToken: string, profile: Profile, done: (error: any, user?: FacebookUser | boolean | null) => void): Promise<void> {
    try {
      const user: FacebookUser = {
        authorizerId: profile.id,
        firstName: profile.name.givenName,
        lastName: profile.name.familyName,
        email:`${profile.id}@facebook.com`,//manipulated data
        loginSource: "facebook",//manipulated data
        // Other user data as needed
      };
      done(null, user);
    } catch (error) {
      done(error, false);
    }
  }
}
