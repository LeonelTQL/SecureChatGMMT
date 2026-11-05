import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { ROLES_KEY } from '../../decorators/roles/roles.decorator';
import { AuthenticatedUser } from '../../interfaces/authenticated-user/authenticated-user.interface';
import { audit } from '../../../common/audit/audit';
@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}
  canActivate(context: ExecutionContext) {
    const roles = this.reflector.getAllAndOverride<string[]>(ROLES_KEY, [context.getHandler(), context.getClass()]);
    if (!roles?.length) return true;
    const user: AuthenticatedUser | undefined = context.switchToHttp().getRequest().user;
    if (!user || !roles.some(role => user.roles.includes(role))) {
      audit('access.denied', { user_id: user?.sub }); throw new ForbiddenException('Permisos insuficientes');
    }
    return true;
  }
}
