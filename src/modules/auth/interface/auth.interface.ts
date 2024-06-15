export interface SignInDataInterface {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
}


export interface ExistingUserDataInterface {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
  password: string;
  verified: boolean;
  isForgetPassword: boolean;
}


export interface TokenInterface {
  accessToken: string;
  refreshToken: string;
}

export interface tokenCreateUserDataInterface {
  id: number;
  email: string;
  firstName: string;
  lastName: string;
  verified: boolean;
  isForgetPassword: boolean;
}

