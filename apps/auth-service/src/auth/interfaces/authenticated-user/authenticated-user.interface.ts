export interface AuthenticatedUser {
  sub: string;
  email: string;
  username: string;
  jti: string;
  exp: number;
}
