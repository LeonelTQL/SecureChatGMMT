import { CanActivate, ExecutionContext, HttpException, Injectable } from '@nestjs/common';
import { createHash } from 'node:crypto';
@Injectable()
export class LoginRateGuard implements CanActivate {
  private windows = new Map<string, { count: number; until: number }>();
  private limit(key: string, max: number) {
    const now = Date.now();
    for (const [k, v] of this.windows) if (v.until <= now) this.windows.delete(k);
    let window = this.windows.get(key);
    if (!window) {
      if (this.windows.size >= 10000) throw new HttpException('Servicio ocupado', 503);
      window = { count: 0, until: now + 60000 }; this.windows.set(key, window);
    }
    if (++window.count > max) throw new HttpException('Demasiados intentos; espera un minuto', 429);
  }
  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    const route = request.path.replace(/^\/api/, '');
    if (request.method === 'POST' && ['/auth/login', '/auth/register'].includes(route)) {
      this.limit(`ip:${request.ip}`, 30);
      if (route.endsWith('login') && typeof request.body?.email === 'string') {
        const digest = createHash('sha256').update(request.body.email.trim().toLowerCase()).digest('hex');
        this.limit(`account:${digest}`, 10);
      }
    }
    return true;
  }
}
