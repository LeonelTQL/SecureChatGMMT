import { Body, Controller, Get, Headers, HttpCode, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto/login.dto';
import { CreateUserDto } from '../users/dto/create-user.dto';
import { audit } from '../common/audit/audit';
import { bearer } from './guards/jwt-auth/bearer';
import { Public } from './decorators/public/public.decorator';
import { CurrentUser } from './decorators/current-user/current-user.decorator';
import { AuthenticatedUser } from './interfaces/authenticated-user/authenticated-user.interface';
@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}
  @Public() @Post('register') register(@Body() dto: CreateUserDto) { return this.auth.register(dto); }
  @Public() @Post('login') @HttpCode(200) login(@Body() dto: LoginDto) { return this.auth.login(dto); }
  @Post('verify') @HttpCode(200) verify(@Headers('authorization') authorization?: string) { return this.auth.verify(bearer(authorization)); }
  @Get('profile') profile(@CurrentUser() user: AuthenticatedUser) {
    const { sub, email, username, roles } = user; return { id: sub, email, username, roles };
  }
  @Post('logout') @HttpCode(204)
  async logout(@CurrentUser() user: AuthenticatedUser) { await this.auth.logout(user.jti); audit('session.revoked', { user_id: user.sub }); }
}
