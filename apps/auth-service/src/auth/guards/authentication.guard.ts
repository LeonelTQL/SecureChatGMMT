import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthService } from '../auth.service';
import { IS_PUBLIC_KEY } from '../decorators/public/public.decorator';
export function bearer(value?: string): string {
  const match = /^Bearer ([^\s]{1,4096})$/i.exec(value ?? '');
  if (!match) throw new UnauthorizedException('Se requiere un token Bearer');
  return match[1];
}
// Autenticación de Leonel. No decide roles ni privilegios administrativos.
@Injectable()
export class AuthenticationGuard implements CanActivate {
  constructor(private readonly reflector: Reflector, private readonly auth: AuthService) {}
  async canActivate(context: ExecutionContext) {
    if (this.reflector.getAllAndOverride(IS_PUBLIC_KEY, [context.getHandler(), context.getClass()])) return true;
    const request = context.switchToHttp().getRequest();
    request.user = await this.auth.verify(bearer(request.headers.authorization));
    return true;
  }
}
