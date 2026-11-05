import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { createHash, timingSafeEqual } from 'node:crypto';
import { AuthService } from '../../auth.service';
import { IS_PUBLIC_KEY } from '../../decorators/public/public.decorator';
import { SERVICE_ONLY_KEY } from '../../decorators/service-only/service-only.decorator';
import { bearer } from './bearer';
import { audit } from '../../../common/audit/audit';
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private readonly reflector: Reflector, private readonly auth: AuthService) {}
  async canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    const targets = [context.getHandler(), context.getClass()];
    if (this.reflector.getAllAndOverride(IS_PUBLIC_KEY, targets)) return true;
    if (this.reflector.getAllAndOverride(SERVICE_ONLY_KEY, targets)) {
      const provided = request.headers['x-service-token'];
      const expected = process.env.STEGO_SERVICE_TOKEN;
      if (typeof provided !== 'string' || !expected || expected.length < 32 || provided.length > 256 ||
          !timingSafeEqual(createHash('sha256').update(provided).digest(), createHash('sha256').update(expected).digest())) {
        audit('service.denied'); throw new UnauthorizedException('Servicio no autenticado');
      }
      return true;
    }
    request.user = await this.auth.verify(bearer(request.headers.authorization));
    return true;
  }
}
