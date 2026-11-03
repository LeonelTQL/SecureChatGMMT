import { Body, Controller, Headers, HttpCode, Post, UnauthorizedException } from '@nestjs/common';
import { AuthService } from './auth.service';
import { CredentialsDto } from './auth.dto';
@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}
  @Post('register')
  register(@Body() dto: CredentialsDto) { return this.auth.register(dto); }
  @Post('login')
  @HttpCode(200)
  login(@Body() dto: CredentialsDto) { return this.auth.login(dto); }
  @Post('verify')
  @HttpCode(200)
  verify(@Headers('authorization') authorization?: string) {
    const match = /^Bearer ([^\s]+)$/i.exec(authorization ?? '');
    if (!match) throw new UnauthorizedException('Se requiere un token Bearer');
    return this.auth.verify(match[1]);
  }
}
