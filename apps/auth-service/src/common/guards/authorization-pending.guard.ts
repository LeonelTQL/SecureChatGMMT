import { CanActivate, Injectable, ServiceUnavailableException } from '@nestjs/common';
@Injectable()
export class AuthorizationPendingGuard implements CanActivate {
  canActivate(): never {
    throw new ServiceUnavailableException('Operación bloqueada hasta integrar la autorización de Alejandro');
  }
}
